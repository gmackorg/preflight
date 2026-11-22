package main

// store.upload for Android (PREFLT-66): the Google Play Developer API in Go,
// no fastlane/supply. Service-account JWT bearer grant (RS256) ->
// edits.insert -> edits.bundles.upload (or apks.upload) -> edits.tracks.update
// -> edits.commit. A failed edit is deleted so it cannot block the next one.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	playPublisherScope    = "https://www.googleapis.com/auth/androidpublisher"
	defaultGoogleTokenURL = "https://oauth2.googleapis.com/token"
)

// playAPIBaseURL is overridden by tests; never pointed at Google in tests.
var playAPIBaseURL = "https://androidpublisher.googleapis.com"

type playPublisher struct {
	client      *http.Client
	baseURL     string
	packageName string
	token       string
}

// playAPIError carries the HTTP status so failures classify as transient.
type playAPIError struct {
	status  int
	message string
}

func (e *playAPIError) Error() string {
	return fmt.Sprintf("Google Play API HTTP %d: %s", e.status, e.message)
}

func playTrackForDestination(destination string) (string, bool) {
	switch destination {
	case "play_internal":
		return "internal", true
	case "play_alpha":
		return "alpha", true
	case "play_beta":
		return "beta", true
	case "play_production":
		return "production", true
	}
	return "", false
}

func fetchGoogleAccessToken(client *http.Client, account googleServiceAccount) (string, error) {
	tokenURL := strings.TrimSpace(account.TokenURI)
	if tokenURL == "" {
		tokenURL = defaultGoogleTokenURL
	}
	account.TokenURI = tokenURL
	assertion, err := googleServiceAccountJWT(account, playPublisherScope, time.Now())
	if err != nil {
		return "", storeFailuref("signing_credential_invalid", "build service account assertion: %v", err)
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return "", &playAPIError{status: 0, message: "token request: " + err.Error()}
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		return "", &playAPIError{status: response.StatusCode, message: "token exchange: " + strings.TrimSpace(string(body))}
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &token); err != nil || token.AccessToken == "" {
		return "", &playAPIError{status: response.StatusCode, message: "token response had no access_token"}
	}
	return token.AccessToken, nil
}

func (p *playPublisher) editsURL(suffix string) string {
	return fmt.Sprintf("%s/androidpublisher/v3/applications/%s/edits%s", p.baseURL, url.PathEscape(p.packageName), suffix)
}

func (p *playPublisher) do(method string, endpoint string, contentType string, body io.Reader, contentLength int64, timeout time.Duration, output any) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	if contentLength >= 0 {
		request.ContentLength = contentLength
	}
	request.Header.Set("Authorization", "Bearer "+p.token)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := p.client.Do(request)
	if err != nil {
		return &playAPIError{status: 0, message: err.Error()}
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := strings.TrimSpace(string(raw))
		var decoded struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &decoded) == nil && decoded.Error.Message != "" {
			message = decoded.Error.Message
		}
		return &playAPIError{status: response.StatusCode, message: message}
	}
	if output != nil && len(bytes.TrimSpace(raw)) > 0 {
		return json.Unmarshal(raw, output)
	}
	return nil
}

func (p *playPublisher) doJSON(method string, endpoint string, payload any, output any) error {
	var body io.Reader = http.NoBody
	length := int64(0)
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
		length = int64(len(raw))
	}
	return p.do(method, endpoint, "application/json", body, length, 2*time.Minute, output)
}

func classifyPlayFailure(step string, err error) *storeFailure {
	if failure, ok := err.(*storeFailure); ok {
		return failure
	}
	if apiErr, ok := err.(*playAPIError); ok {
		switch {
		case apiErr.status == 0 || apiErr.status == http.StatusTooManyRequests || apiErr.status >= 500:
			return storeFailuref("play_upload_transient", "%s: %v", step, err)
		case apiErr.status == http.StatusUnauthorized || apiErr.status == http.StatusForbidden:
			return storeFailuref("play_auth_failed", "%s: %v", step, err)
		}
		return storeFailuref("play_upload_rejected", "%s: %v", step, err)
	}
	return storeFailuref("play_upload_failed", "%s: %v", step, err)
}

func playDraftAppError(err error) bool {
	apiErr, ok := err.(*playAPIError)
	if !ok {
		return false
	}
	lower := strings.ToLower(apiErr.message)
	return strings.Contains(lower, "draft app") || strings.Contains(lower, "status draft")
}

type playUploadRequest struct {
	packageName  string
	artifactPath string
	kind         string
	track        string
	releaseNotes string
	releaseName  string
}

// publishToPlay runs one edit end to end and returns the uploaded versionCode
// and the release status that was committed.
func publishToPlay(client *http.Client, baseURL string, account googleServiceAccount, request playUploadRequest) (string, string, error) {
	token, err := fetchGoogleAccessToken(client, account)
	if err != nil {
		return "", "", classifyPlayFailure("authenticate", err)
	}
	release := registerRedactedSecrets(token)
	defer release()
	publisher := &playPublisher{client: client, baseURL: strings.TrimRight(baseURL, "/"), packageName: request.packageName, token: token}

	var edit struct {
		ID string `json:"id"`
	}
	if err := publisher.doJSON(http.MethodPost, publisher.editsURL(""), map[string]any{}, &edit); err != nil {
		return "", "", classifyPlayFailure("edits.insert", err)
	}
	if edit.ID == "" {
		return "", "", storeFailuref("play_upload_failed", "edits.insert returned no edit id")
	}
	committed := false
	defer func() {
		if !committed {
			_ = publisher.doJSON(http.MethodDelete, publisher.editsURL("/"+url.PathEscape(edit.ID)), nil, nil)
		}
	}()

	file, err := os.Open(request.artifactPath)
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", "", err
	}
	collection := "bundles"
	if request.kind == "apk" {
		collection = "apks"
	}
	uploadURL := fmt.Sprintf("%s/upload/androidpublisher/v3/applications/%s/edits/%s/%s?uploadType=media",
		publisher.baseURL, url.PathEscape(request.packageName), url.PathEscape(edit.ID), collection)
	var uploaded struct {
		VersionCode json.Number `json:"versionCode"`
	}
	if err := publisher.do(http.MethodPost, uploadURL, "application/octet-stream", file, info.Size(),
		durationFromEnv("PREFLIGHT_PLAY_UPLOAD_TIMEOUT", 30*time.Minute), &uploaded); err != nil {
		return "", "", classifyPlayFailure("edits."+collection+".upload", err)
	}
	versionCode := uploaded.VersionCode.String()
	if versionCode == "" {
		return "", "", storeFailuref("play_upload_failed", "upload response had no versionCode")
	}

	trackRelease := func(status string) map[string]any {
		releaseBody := map[string]any{
			"versionCodes": []string{versionCode},
			"status":       status,
		}
		if request.releaseName != "" {
			releaseBody["name"] = request.releaseName
		}
		if notes := strings.TrimSpace(request.releaseNotes); notes != "" {
			releaseBody["releaseNotes"] = []map[string]string{{"language": "en-US", "text": notes}}
		}
		return map[string]any{"track": request.track, "releases": []map[string]any{releaseBody}}
	}
	trackURL := publisher.editsURL("/" + url.PathEscape(edit.ID) + "/tracks/" + url.PathEscape(request.track))
	status := "completed"
	if err := publisher.doJSON(http.MethodPut, trackURL, trackRelease(status), nil); err != nil {
		if !playDraftAppError(err) {
			return "", "", classifyPlayFailure("edits.tracks.update", err)
		}
		// An app that has never been published only accepts draft releases.
		status = "draft"
		if err := publisher.doJSON(http.MethodPut, trackURL, trackRelease(status), nil); err != nil {
			return "", "", classifyPlayFailure("edits.tracks.update (draft)", err)
		}
	}
	if err := publisher.doJSON(http.MethodPost, publisher.editsURL("/"+url.PathEscape(edit.ID)+":commit"), nil, nil); err != nil {
		return "", "", classifyPlayFailure("edits.commit", err)
	}
	committed = true
	return versionCode, status, nil
}

func runPlayStoreUpload(rt *storeJobRuntime, job apiRunnerJob, artifact storeBuildArtifact, artifactPath string, destination string) (map[string]any, error) {
	track, _ := playTrackForDestination(destination)
	packageName := strings.TrimSpace(job.Payload.ApplicationID)
	if packageName == "" {
		return nil, storeFailuref("store_upload_payload_invalid", "Play upload requires applicationId")
	}
	referenceID := storeSecretReferenceFor(job, "play_service_account", "GOOGLE_PLAY_SERVICE_ACCOUNT_JSON")
	revealed, err := revealStoreSecret(rt.reveal, rt.cleanup, referenceID, "Google Play service account")
	if err != nil {
		return nil, err
	}
	var payload googleServiceAccountPayload
	if err := parseStoreSecretPayload("play_service_account", revealed.Value, &payload, "serviceAccountJson", "clientEmail", "projectId"); err != nil {
		return nil, err
	}
	var account googleServiceAccount
	if err := json.Unmarshal([]byte(payload.ServiceAccountJSON), &account); err != nil || account.PrivateKey == "" || account.ClientEmail == "" {
		return nil, storeFailuref("signing_credential_invalid", "play_service_account serviceAccountJson is not a service account key")
	}
	registerPayloadSecrets(rt.cleanup, account.PrivateKey, payload.ServiceAccountJSON)
	kind := artifact.Kind
	if kind == "" {
		kind = "aab"
	}
	releaseName := strings.TrimSpace(job.Payload.Version)
	if releaseName != "" && job.Payload.BuildNumber != "" {
		releaseName = fmt.Sprintf("%s (%s)", releaseName, job.Payload.BuildNumber)
	}
	_, _ = fmt.Fprintf(rt.log, "uploading %s to Google Play %s track (%s)\n", artifact.FileName, track, packageName)
	versionCode, status, err := publishToPlay(&http.Client{}, playAPIBaseURL, account, playUploadRequest{
		packageName:  packageName,
		artifactPath: artifactPath,
		kind:         kind,
		track:        track,
		releaseNotes: job.Payload.ReleaseNotes,
		releaseName:  releaseName,
	})
	if err != nil {
		return nil, err
	}
	if expected := strings.TrimSpace(job.Payload.BuildNumber); expected != "" {
		if _, parseErr := strconv.ParseInt(expected, 10, 64); parseErr == nil && expected != versionCode {
			_, _ = fmt.Fprintf(rt.log, "warning: Play reports versionCode %s, build number was %s\n", versionCode, expected)
		}
	}
	return map[string]any{
		"status":            "ok",
		"buildId":           job.Payload.BuildID,
		"destination":       destination,
		"playVersionCode":   versionCode,
		"playTrack":         track,
		"playReleaseStatus": status,
		"artifact":          artifact.toMap(),
	}, nil
}
