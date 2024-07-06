package auth

// TokenPair defines entity model for access & resfresh jwt token pair.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
}
