package auth

import "testing"

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("expected password to verify")
	}
	if VerifyPassword(hash, "wrong") {
		t.Fatal("wrong password verified")
	}
}

func TestStoreBootstrapAndAuthenticate(t *testing.T) {
	store, err := Open(t.TempDir() + "/users.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BootstrapAdmin("root", "secret"); err != nil {
		t.Fatal(err)
	}
	user, perms, ok := store.Authenticate("root", "secret")
	if !ok {
		t.Fatal("admin did not authenticate")
	}
	if user.Username != "root" || !perms.Admin || !perms.Upload || !perms.Delete {
		t.Fatalf("unexpected admin auth result: %#v %#v", user, perms)
	}
}

func TestUpsertUserIgnoresSuppliedPasswordHash(t *testing.T) {
	store, err := Open(t.TempDir() + "/users.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertUser(User{Username: "mallory", PasswordHash: "pbkdf2-sha256$1$bad$bad", Home: "/mallory", Permissions: ReadOnlyPermissions()}, ""); err == nil {
		t.Fatal("expected password to be required when only password_hash is supplied")
	}
}

func TestCannotDeleteOrDisableLastAdmin(t *testing.T) {
	store, err := Open(t.TempDir() + "/users.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BootstrapAdmin("admin", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteUser("admin"); err != ErrLastAdmin {
		t.Fatalf("expected ErrLastAdmin deleting only admin, got %v", err)
	}
	admin, _, ok := store.Permissions("admin")
	if !ok {
		t.Fatal("admin missing")
	}
	admin.Disabled = true
	if err := store.UpsertUser(admin, ""); err != ErrLastAdmin {
		t.Fatalf("expected ErrLastAdmin disabling only admin, got %v", err)
	}
}
