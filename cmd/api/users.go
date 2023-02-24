package main

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/nkadirgali/go/internal/data"
	"github.com/nkadirgali/go/internal/validator"
)

func (app *application) registerUserHandler(w http.ResponseWriter, r *http.Request) {
	// Create an anonymous struct to hold the expected data from the request body.
	var input struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	// Parse the request body into the anonymous struct.
	err := app.readJSON(w, r, &input)
	if err != nil {
		app.badRequestResponse(w, r, err)
		return
	}
	// Copy the data from the request body into a new User struct. Notice also that we
	// set the Activated field to false, which isn't strictly necessary because the
	// Activated field will have the zero-value of false by default. But setting this
	// explicitly helps to make our intentions clear to anyone reading the code.
	user := &data.User{
		Username: input.Username,
		Email:    input.Email,
		//		Activated: false,
	}
	// Use the Password.Set() method to generate and store the hashed and plaintext
	// passwords.
	err = user.Password.Set(input.Password)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}
	v := validator.New()
	// Validate the user struct and return the error messages to the client if any of
	// the checks fail.
	if data.ValidateUser(v, user); !v.Valid() {
		app.failedValidationResponse(w, r, v.Errors)
		return
	}
	// Insert the user data into the database.
	err = app.models.Users.Insert(user)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrDuplicateEmail):
			v.AddError("email", "a user with this email address already exists")
			app.failedValidationResponse(w, r, v.Errors)
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}
	// After the user record has been created in the database, generate a new activation
	// token for the user.
	token, err := app.models.Tokens.New(user.ID, 3*24*time.Hour, data.ScopeActivation)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}
	app.background(func() {
		// As there are now multiple pieces of data that we want to pass to our email
		// templates, we create a map to act as a 'holding structure' for the data. This
		// contains the plaintext version of the activation token for the user, along
		// with their ID.
		data := map[string]any{
			"activationToken": token.Plaintext,
			"userID":          user.ID,
		}
		// Send the welcome email, passing in the map above as dynamic data.
		err = app.mailer.Send(user.Email, "user_welcome.tmpl", data)
		if err != nil {
			app.logger.PrintError(err, nil)
		}
	})
	err = app.writeJSON(w, http.StatusAccepted, envelope{"user": user}, nil)
	if err != nil {
		app.serverErrorResponse(w, r, err)
	}
}

/*
func (app *application) activateUserHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the plaintext activation token from the request body.
	var input struct {
		TokenPlaintext string `json:"token"`
	}
	err := app.readJSON(w, r, &input)
	if err != nil {
		app.badRequestResponse(w, r, err)
		return
	}
	// Validate the plaintext token provided by the client.
	v := validator.New()
	if data.ValidateTokenPlaintext(v, input.TokenPlaintext); !v.Valid() {
		app.failedValidationResponse(w, r, v.Errors)
		return
	}
	// Retrieve the details of the user associated with the token using the
	// GetForToken() method (which we will create in a minute). If no matching record
	// is found, then we let the client know that the token they provided is not valid.
	user, err := app.models.Users.GetForToken(data.ScopeActivation, input.TokenPlaintext)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			v.AddError("token", "invalid or expired activation token")
			app.failedValidationResponse(w, r, v.Errors)
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}
	// Update the user's activation status.
	user.Activated = true
	// Save the updated user record in our database, checking for any edit conflicts in
	// the same way that we did for our movie records.
	err = app.models.Users.Update(user)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrEditConflict):
			app.editConflictResponse(w, r)
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}
	// If everything went successfully, then we delete all activation tokens for the
	// user.
	err = app.models.Tokens.DeleteAllForUser(data.ScopeActivation, user.ID)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}
	// Send the updated user details to the client in a JSON response.
	err = app.writeJSON(w, http.StatusOK, envelope{"user": user}, nil)
	if err != nil {
		app.serverErrorResponse(w, r, err)
	}
}*/

func (app *application) createRoleHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the plaintext activation token from the request body.
	var input struct {
		Role_Name string `json:"role_name"`
		UserID    int    `json:"user_id"`
	}

	err := app.readJSON(w, r, &input)
	if err != nil {
		app.badRequestResponse(w, r, err)
		return
	}
	user, err := app.models.Users.GetByID(input.UserID)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}
	role := &data.Role{
		Role_Name: input.Role_Name,
		UserID:    input.UserID,
	}
	err = app.models.Roles.Insert(role)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	err = app.writeJSON(w, http.StatusOK, envelope{"role": role, "user": user}, nil)
	if err != nil {
		app.serverErrorResponse(w, r, err)
	}
}

/*
func (app *application) isAuthenticated(w http.ResponseWriter, r *http.Request) {
//	token := r.Header.Get("token")
//	app.models.Tokens.

		// Parse the plaintext activation token from the request body.
		var input struct {
			token string `json:"token"`
		}

		err := app.readJSON(w, r, &input)
		if err != nil {
			app.badRequestResponse(w, r, err)
			return
		}
		user, err := app.models.Users.GetByID(input.UserID)
		if err != nil {
			app.serverErrorResponse(w, r, err)
			return
		}
		role := &data.Role{
			Role_Name: input.Role_Name,
			UserID:    input.UserID,
		}
		err = app.models.Roles.Insert(role)
		if err != nil {
			app.serverErrorResponse(w, r, err)
			return
		}

		err = app.writeJSON(w, http.StatusOK, envelope{"role": role, "user": user}, nil)
		if err != nil {
			app.serverErrorResponse(w, r, err)
		}
	}
*/
func (app *application) login(w http.ResponseWriter, r *http.Request) {
	loginTempl, err := template.ParseFiles("./templates/login.html", "./templates/links1.html")
	if err != nil {
		app.serverErrorResponse(w, r, err)
	}
	loginTempl.ExecuteTemplate(w, "login", "")
}

func (app *application) userLogin(w http.ResponseWriter, r *http.Request) {
	// Create an anonymous struct to hold the expected data from the request body.
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	input.Username = r.FormValue("username")
	input.Password = r.FormValue("password")

	// Validate the email and password provided by the client.
	v := validator.New()
	data.ValidatePasswordPlaintext(v, input.Password)
	if !v.Valid() {
		app.failedValidationResponse(w, r, v.Errors)
		return
	}
	// Lookup the user record based on the email address. If no matching user was
	// found, then we call the app.invalidCredentialsResponse() helper to send a 401
	// Unauthorized response to the client (we will create this helper in a moment).
	user, err := app.models.Users.GetByUsername(input.Username)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			app.invalidCredentialsResponse(w, r)
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}
	// Check if the provided password matches the actual password for the user.
	match, err := user.Password.Matches(input.Password)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}
	// If the passwords don't match, then we call the app.invalidCredentialsResponse()
	// helper again and return.
	if !match {
		app.invalidCredentialsResponse(w, r)
		return
	}
	// Otherwise, if the password is correct, we generate a new token with a 24-hour
	// expiry time and the scope 'authentication'.
	token, err := app.models.Tokens.New(user.ID, 24*time.Hour, data.ScopeAuthentication)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}
	// Encode the token to JSON and send it in the response along with a 201 Created
	// status code.
	r.Header = http.Header{
		"userid": {fmt.Sprint(user.ID)},
		"token1": {token.Plaintext},
	}
	r.Header.Set("id", fmt.Sprint(user.ID))
	r.Header.Set("token3", token.Plaintext)
	fmt.Println("userLoginToken=", token.Plaintext)
	fmt.Println("userId=", user.ID)
	w.Header().Set("token2", token.Plaintext)
	w.Header().Set("id", fmt.Sprint(user.ID))
	app.feed(w, r)
	//	http.Redirect(w, r, "/", http.StatusSeeOther)
	// err = app.writeJSON(w, http.StatusCreated, envelope{"authentication_token": token}, r.Header)
	// if err != nil {
	// 	app.serverErrorResponse(w, r, err)
	// }
}

func (app *application) register(w http.ResponseWriter, r *http.Request) {
	loginTempl, err := template.ParseFiles("./templates/register.html", "./templates/links1.html")
	if err != nil {
		app.serverErrorResponse(w, r, err)
	}
	loginTempl.ExecuteTemplate(w, "register", "")
}

func (app *application) registerUser(w http.ResponseWriter, r *http.Request) {
	// Create an anonymous struct to hold the expected data from the request body.
	var input struct {
		Username  string `json:"username"`
		Firstname string `json:"firstname"`
		Lastname  string `json:"lastname"`
		Email     string `json:"email"`
		Password  string `json:"password"`
	}
	input.Username = r.FormValue("username")
	input.Firstname = r.FormValue("firstName")
	input.Lastname = r.FormValue("lastName")
	input.Email = r.FormValue("email")
	input.Password = r.FormValue("password")

	user := &data.User{
		Username:  input.Username,
		Firstname: input.Firstname,
		Lastname:  input.Lastname,
		Email:     input.Email,
	}
	// Use the Password.Set() method to generate and store the hashed and plaintext
	// passwords.
	err := user.Password.Set(input.Password)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}
	v := validator.New()
	// Validate the user struct and return the error messages to the client if any of
	// the checks fail.
	if data.ValidateUser(v, user); !v.Valid() {
		app.failedValidationResponse(w, r, v.Errors)
		return
	}
	// Insert the user data into the database.
	err = app.models.Users.Insert(user)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrDuplicateEmail):
			v.AddError("email", "a user with this email address already exists")
			app.failedValidationResponse(w, r, v.Errors)
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}
	// After the user record has been created in the database, generate a new activation
	// token for the user.
	/*	token, err := app.models.Tokens.New(user.ID, 3*24*time.Hour, data.ScopeActivation)
		if err != nil {
			app.serverErrorResponse(w, r, err)
			return
		}
		app.background(func() {
			// As there are now multiple pieces of data that we want to pass to our email
			// templates, we create a map to act as a 'holding structure' for the data. This
			// contains the plaintext version of the activation token for the user, along
			// with their ID.
			data := map[string]any{
				"activationToken": token.Plaintext,
				"userID":          user.ID,
			}
			// Send the welcome email, passing in the map above as dynamic data.
			err = app.mailer.Send(user.Email, "user_welcome.tmpl", data)
			if err != nil {
				app.logger.PrintError(err, nil)
			}
		})*/
	app.userLogin(w, r)
	//	http.Redirect(w, r, "/", http.StatusSeeOther)
	/*	err = app.writeJSON(w, http.StatusAccepted, envelope{"user": user}, nil)
		if err != nil {
			app.serverErrorResponse(w, r, err)
		}*/
}

func (app *application) feed(w http.ResponseWriter, r *http.Request) {
	header := w.Header().Clone()
	token1 := r.Header.Get("token1")
	token2 := header.Get("token2")
	token3 := r.Header.Get("token3")
	id := header.Get("id")
	fmt.Println("token = |", token1, "token = |", token2, "id = |", id, token3)
	loginTempl, err := template.ParseFiles("./templates/index1.html", "./templates/links1.html", "./templates/navsidebar.html", "./templates/header.html")
	if err != nil {
		app.serverErrorResponse(w, r, err)
	}
	w.Header().Set("token2", token2)
	w.Header().Set("id", id)
	r.Header.Set("token2", token2)
	r.Header.Set("id", id)
	loginTempl.ExecuteTemplate(w, "index1", "")
}

func (app *application) allUsers(w http.ResponseWriter, r *http.Request) {
	fmt.Println("all", r.Header.Get("token3"))
	fmt.Println("all", w.Header().Get("token2"))
	fmt.Println("all", r.Header.Get("token2"))
	//	w.Header().Set("token2", w.)
	users, err := app.models.Users.GetAllUsers()

	loginTempl, err := template.ParseFiles("./templates/findUser.html", "./templates/links1.html", "./templates/navsidebar.html", "./templates/header1.html")
	if err != nil {
		app.serverErrorResponse(w, r, err)
	}

	loginTempl.ExecuteTemplate(w, "findUser", users)
}

func (app *application) profile(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.Header.Get("token2"))
	fmt.Println("token = |", w.Header().Get("token2"))
	fmt.Println("token1 = |", r.Header.Get("token2"))
	fmt.Println("token2 = |", r.Header.Get("id"))
	fmt.Println("epta", w.Header().Clone().Values("id"))
	fmt.Println("header", w.Header().Get("Id"))
	userId := r.Header.Get("id")
	fmt.Println("user_id = |", userId)
	url1 := r.URL
	strurl := string(url1.Path)
	username := strurl[6:]
	fmt.Println("username", username)
	var input struct {
		Username        string
		Firstname       string
		Lastname        string
		KolPublications int
		KolFollowers    int
		KolFollowings   int
		Posts           []*data.Post
	}
	if userId == "" {
		fmt.Println("asln")
		loginTempl, err := template.ParseFiles("./templates/otherProfile.html", "./templates/links1.html", "./templates/navsidebar.html", "./templates/header1.html")
		if err != nil {
			app.serverErrorResponse(w, r, err)
		}

		user, err := app.models.Users.GetByUsername(username)
		if err != nil {
			app.serverErrorResponse(w, r, err)
			return
		}
		posts, err := app.models.Posts.GetAll(int(user.ID))
		if err != nil {
			app.serverErrorResponse(w, r, err)
			return
		}
		var postsR []*data.Post
		for i := len(posts) - 1; i >= 0; i-- {
			postsR = append(postsR, posts[i])
		}
		input.Username = user.Username
		input.Firstname = user.Firstname
		input.Lastname = user.Lastname
		input.KolPublications = len(posts)
		input.KolFollowers = 0
		input.KolFollowings = 0
		input.Posts = postsR
		fmt.Println(input)
		loginTempl.ExecuteTemplate(w, "otherProfile", input)
	} else {
		fmt.Println("else")
		user_id, err := strconv.Atoi(userId)
		if err != nil {
			app.serverErrorResponse(w, r, err)
			return
		}
		user, err := app.models.Users.GetByID(user_id)
		fmt.Println("userUsermna", user.Username)
		if err != nil {
			app.serverErrorResponse(w, r, err)
			return
		}
		if user.Username == username {
			loginTempl, err := template.ParseFiles("./templates/profile.html", "./templates/links1.html", "./templates/navsidebar.html", "./templates/header.html")
			if err != nil {
				app.serverErrorResponse(w, r, err)
			}
			posts, err := app.models.Posts.GetAll(user_id)
			if err != nil {
				app.serverErrorResponse(w, r, err)
				return
			}
			input.Username = user.Username
			input.Firstname = user.Firstname
			input.Lastname = user.Lastname
			input.KolPublications = len(posts)
			input.KolFollowers = 0
			input.KolFollowings = 0
			input.Posts = posts
			loginTempl.ExecuteTemplate(w, "profile", input)
		} else {
			loginTempl, err := template.ParseFiles("./templates/otherProfile.html", "./templates/links1.html", "./templates/navsidebar.html", "./templates/header1.html")
			if err != nil {
				app.serverErrorResponse(w, r, err)
			}
			posts, err := app.models.Posts.GetAll(user_id)
			if err != nil {
				app.serverErrorResponse(w, r, err)
				return
			}
			input.Username = user.Username
			input.Firstname = user.Firstname
			input.Lastname = user.Lastname
			input.KolPublications = len(posts)
			input.KolFollowers = 0
			input.KolFollowings = 0
			input.Posts = posts

			loginTempl.ExecuteTemplate(w, "otherProfile", input)
		}
	}
}
