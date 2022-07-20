package ocm

type LoginProofInvitationResponse struct {
	StatusCode int                              `json:"statusCode"`
	Message    string                           `json:"message"`
	Data       LoginProofInvitationResponseData `json:"data"`
}

type LoginProofInvitationResponseData struct {
	PresentationID      string `json:"presentationId"`
	PresentationMessage string `json:"presentationMessage"`
}

type LoginProofResultResponse struct {
	StatusCode int                          `json:"statusCode"`
	Message    string                       `json:"message"`
	Data       LoginProofResultResponseData `json:"data"`
}

type LoginProofResultResponseData struct {
	State     string                 `json:"state"`
	SchemaID  string                 `json:"schemaId"`
	CredDefID string                 `json:"credDefId"`
	Claims    map[string]interface{} `json:"credentialSubject"`
}
