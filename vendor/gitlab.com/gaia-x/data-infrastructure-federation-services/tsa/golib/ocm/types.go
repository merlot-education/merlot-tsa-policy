package ocm

type LoginProofInvitationResponse struct {
	StatusCode int                              `json:"statusCode"`
	Message    string                           `json:"message"`
	Data       LoginProofInvitationResponseData `json:"data"`
}

type LoginProofInvitationResponseData struct {
	ProofRecordID       string `json:"proofRecordId"`
	PresentationMessage string `json:"presentationMessage"`
}

type LoginProofResultResponse struct {
	StatusCode int                          `json:"statusCode"`
	Message    string                       `json:"message"`
	Data       LoginProofResultResponseData `json:"data"`
}

type LoginProofResultResponseData struct {
	State         string         `json:"state"`
	Presentations []Presentation `json:"presentations"`
}

type Presentation struct {
	SchemaID  string                 `json:"schemaId"`
	CredDefID string                 `json:"credDefId"`
	Claims    map[string]interface{} `json:"credentialSubject"`
}
