-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
  gen_random_uuid(),
  NOW(),
  NOW(),
  $1,
  $2
)
RETURNING id, created_at, updated_at, email;

-- name: GetUserWithPasswordByEmail :one
SELECT * FROM users
WHERE $1 = email;

-- name: DeleteAllUsers :exec
DELETE FROM users;
