package main

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func (app *application) routes() http.Handler {
	// Initialize a new httprouter router instance.
	router := httprouter.New()
	router.NotFound = http.HandlerFunc(app.notFoundResponse)
	router.MethodNotAllowed = http.HandlerFunc(app.methodNotAllowedResponse)
	// Register the relevant methods, URL patterns and handler functions for our
	// endpoints using the HandlerFunc() method. Note that http.MethodGet and
	// http.MethodPost are constants which equate to the strings "GET" and "POST"
	// respectively.
	router.HandlerFunc(http.MethodGet, "/v1/healthcheck", app.healthcheckHandler)

	router.HandlerFunc(http.MethodGet, "/v1/movies", app.listMoviesHandler)
	router.HandlerFunc(http.MethodGet, "/v1/movies/:id", app.showMovieHandler)
	router.HandlerFunc(http.MethodPost, "/v1/movies", app.createMovieHandler)
	router.HandlerFunc(http.MethodPatch, "/v1/movies/:id", app.updateMovieHandler)
	router.HandlerFunc(http.MethodDelete, "/v1/movies/:id", app.deleteMovieHandler)

	router.HandlerFunc(http.MethodGet, "/v1/directors", app.listDirectorsHandler)
	router.HandlerFunc(http.MethodPost, "/v1/directors", app.createDirectorHandler)
	router.HandlerFunc(http.MethodGet, "/v1/directors/:id", app.showDirectorHandler)

	router.HandlerFunc(http.MethodPost, "/v1/users", app.registerUserHandler)
	//	router.HandlerFunc(http.MethodPut, "/v1/users/activated", app.activateUserHandler)
	router.HandlerFunc(http.MethodPost, "/v1/tokens/authentication", app.createAuthenticationTokenHandler)

	router.HandlerFunc(http.MethodPost, "/v1/roles", app.createRoleHandler)

	router.HandlerFunc(http.MethodGet, "/login", app.login)
	router.HandlerFunc(http.MethodPost, "/user/login", app.userLogin)
	router.HandlerFunc(http.MethodGet, "/register", app.register)
	router.HandlerFunc(http.MethodPost, "/user", app.registerUser)
	router.HandlerFunc(http.MethodGet, "/user", app.allUsers)
	router.HandlerFunc(http.MethodGet, "/user/:username", app.profile)

	router.HandlerFunc(http.MethodGet, "/", app.feed)

	router.HandlerFunc(http.MethodPost, "/post/create", app.createPostHandler)
	router.HandlerFunc(http.MethodDelete, "/post/delete/:id", app.deletePostHandler)

	// Return the httprouter instance.
	return app.recoverPanic(app.rateLimit(app.authenticate(router)))

}
