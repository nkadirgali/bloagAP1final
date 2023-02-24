package main

import (
	"net/http"
	"time"
)

func (app *application) healthcheckHandler(w http.ResponseWriter, r *http.Request) {
	data := envelope{
		"status": "available",
		"system_info": map[string]string{
			"environment": app.config.env,
			"version":     version,
		},
	}

	time.Sleep(4 * time.Second)

	// passing data to json.Marshal() func
	err := app.writeJSON(w, http.StatusOK, data, nil)

	if err != nil {
		app.serverErrorResponse(w, r, err)
	}

}
