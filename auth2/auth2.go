package auth2

type Auth interface {
	Signup(appId, email, password string) (confirmationToken string, err error)
	ConfirmSignup(confirmationToken string) error
	ResendConfirmationToken(appId, email string) (confirmationToken string, err error)
	Signin(appId, email, password string) (sessionToken string, err error)
	Signout(userId string) error
	ForgotPasword(appId, email string) (resetToken string, err error)
	ResetPassword(resetToken, newPassword string) error
	ChangePassword(userId, oldPassword, newPassword string) error
	ChangeEmail(userId, password, newEmail string) error
	GetAllUsers() ([]UserView, error)
	GetUsersByAppId(appId string) ([]UserView, error)
	CreateUser(appId, email, password string) error
	ChangeUserPassword(userId, newPassword string) error
	ChangeUserEmail(userId, newEmail string) error
	RemoveUserById(userId string) error
}

type UserView struct {
	Id    string
	AppId string
	Email string
}

type Mailer interface {
	Start() error
}
