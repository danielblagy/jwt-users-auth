# jwt-users-auths

## Get package

```
go get github.com/danielblagy/jwt-users-auth
```

## Generate password hash

```
import "github.com/danielblagy/jwt-users-auth/hash"

func main() {
    ...

    passwordHash, err := hash.CreatePasswordHash(userPassword)
    if err != nil {
        return errors.Wrap(err, "can't create password hash")
    }

    ...
}
```

Users storage must have user's hashed passwords.

## auth.AuthService

To use the service you must implement auth.BlacklistStore and auth.UsersProvider interfaces.