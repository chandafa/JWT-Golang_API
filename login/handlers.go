package login

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

type Response struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Mahasiswa struct {
	ID           int    `json:"id"`
	Nama         string `json:"nama"`
	NIM          string `json:"nim"`
	JenisKelamin string `json:"jenis_kelamin"`
	Jurusan      string `json:"jurusan"`
}

// SuccessResponse formats the successful response
func SuccessResponse(w http.ResponseWriter, status int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{
		Status:  status,
		Message: message,
		Data:    data,
	})
}

// ErrorResponse formats the error response
func ErrorResponse(w http.ResponseWriter, status int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{
		Status:  status,
		Message: message,
		Data:    data,
	})
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var u User
	json.NewDecoder(r.Body).Decode(&u)

	// Query database for user
	var storedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", u.Username).Scan(&storedPassword)
	if err == sql.ErrNoRows {
		ErrorResponse(w, http.StatusUnauthorized, "Invalid username or password", nil)
		return
	} else if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Error accessing database", nil)
		return
	}

	// Compare hashed password
	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(u.Password))
	if err != nil {
		ErrorResponse(w, http.StatusUnauthorized, "Invalid username or password", nil)
		return
	}

	// Generate JWT token
	tokenString, err := CreateToken(u.Username)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Could not create token", nil)
		return
	}

	// Respond with success and token
	SuccessResponse(w, http.StatusOK, "success", map[string]string{
		"token": tokenString,
	})
}

// RegisterHandler handles user registration
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var u User
	json.NewDecoder(r.Body).Decode(&u)

	// Validate the input
	if u.Username == "" || u.Password == "" {
		ErrorResponse(w, http.StatusBadRequest, "Username and password cannot be empty", nil)
		return
	}

	// Check if username already exists
	var existingUser string
	err := db.QueryRow("SELECT username FROM users WHERE username = ?", u.Username).Scan(&existingUser)
	if err == nil {
		ErrorResponse(w, http.StatusConflict, "Username already exists", nil)
		return
	} else if err != sql.ErrNoRows {
		ErrorResponse(w, http.StatusInternalServerError, "Error checking existing user", nil)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Error hashing password", nil)
		return
	}

	// Insert the new user into the database
	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", u.Username, string(hashedPassword))
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Error saving user", nil)
		return
	}

	// Respond with success
	SuccessResponse(w, http.StatusCreated, "User registered successfully", nil)
}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		ErrorResponse(w, http.StatusUnauthorized, "Missing authorization header", nil)
		return
	}
	tokenString = tokenString[len("Bearer "):]

	err := verifyToken(tokenString)
	if err != nil {
		ErrorResponse(w, http.StatusUnauthorized, "Invalid token", nil)
		return
	}

	SuccessResponse(w, http.StatusOK, "success", map[string]string{
		"message": "Welcome to the protected area",
	})
}

// CreateMahasiswa handles creating a new mahasiswa
func CreateMahasiswa(w http.ResponseWriter, r *http.Request) {
	var m Mahasiswa
	json.NewDecoder(r.Body).Decode(&m)

	// Validate input
	if m.Nama == "" || m.NIM == "" || m.JenisKelamin == "" || m.Jurusan == "" {
		ErrorResponse(w, http.StatusBadRequest, "All fields are required", nil)
		return
	}

	// Insert mahasiswa into database
	_, err := db.Exec("INSERT INTO mahasiswa (nama, nim, jenis_kelamin, jurusan) VALUES (?, ?, ?, ?)", m.Nama, m.NIM, m.JenisKelamin, m.Jurusan)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Error creating mahasiswa", nil)
		return
	}

	// Respond with success
	SuccessResponse(w, http.StatusCreated, "Mahasiswa created successfully", nil)
}

// GetMahasiswa handles fetching all mahasiswa
func GetMahasiswa(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, nama, nim, jenis_kelamin, jurusan FROM mahasiswa")
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Error fetching mahasiswa", nil)
		return
	}
	defer rows.Close()

	var mahasiswas []Mahasiswa
	for rows.Next() {
		var m Mahasiswa
		if err := rows.Scan(&m.ID, &m.Nama, &m.NIM, &m.JenisKelamin, &m.Jurusan); err != nil {
			ErrorResponse(w, http.StatusInternalServerError, "Error scanning mahasiswa", nil)
			return
		}
		mahasiswas = append(mahasiswas, m)
	}

	SuccessResponse(w, http.StatusOK, "success", mahasiswas)
}

// UpdateMahasiswa handles updating an existing mahasiswa
func UpdateMahasiswa(w http.ResponseWriter, r *http.Request) {
	var m Mahasiswa
	json.NewDecoder(r.Body).Decode(&m)

	// Validate input
	if m.ID == 0 || m.Nama == "" || m.NIM == "" || m.JenisKelamin == "" || m.Jurusan == "" {
		ErrorResponse(w, http.StatusBadRequest, "All fields are required", nil)
		return
	}

	// Update mahasiswa in database
	_, err := db.Exec("UPDATE mahasiswa SET nama=?, nim=?, jenis_kelamin=?, jurusan=? WHERE id=?", m.Nama, m.NIM, m.JenisKelamin, m.Jurusan, m.ID)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Error updating mahasiswa", nil)
		return
	}

	SuccessResponse(w, http.StatusOK, "Mahasiswa updated successfully", nil)
}

// DeleteMahasiswa handles deleting an existing mahasiswa
func DeleteMahasiswa(w http.ResponseWriter, r *http.Request) {
	var m Mahasiswa
	json.NewDecoder(r.Body).Decode(&m)

	// Validate input
	if m.ID == 0 {
		ErrorResponse(w, http.StatusBadRequest, "ID is required", nil)
		return
	}

	// Delete mahasiswa from database
	_, err := db.Exec("DELETE FROM mahasiswa WHERE id=?", m.ID)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Error deleting mahasiswa", nil)
		return
	}

	SuccessResponse(w, http.StatusOK, "Mahasiswa deleted successfully", nil)
}

func TokenValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			ErrorResponse(w, http.StatusUnauthorized, "Missing authorization header", nil)
			return
		}
		tokenString = tokenString[len("Bearer "):]

		err := verifyToken(tokenString)
		if err != nil {
			ErrorResponse(w, http.StatusUnauthorized, "Invalid token", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}
