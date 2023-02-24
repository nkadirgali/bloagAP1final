package main

import (
	"net/http"
	"strconv"
	"time"

	"github.com/nkadirgali/go/internal/data"
)

func (app *application) createPostHandler(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Text    string
		User_id int
		Date    time.Time
	}

	userId := r.Header.Get("id")
	if userId == "" {
		app.errorResponse(w, r, 211, "you cant create post because youre not logined")
		return
	}
	input.User_id, _ = strconv.Atoi(userId)
	input.Text = r.FormValue("text")

	post := &data.Post{
		Text:   input.Text,
		UserID: input.User_id,
		Date:   time.Now(),
	}

	err := app.models.Posts.Insert(post)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *application) deletePostHandler(w http.ResponseWriter, r *http.Request) {
	url1 := r.URL
	strurl := string(url1.Path)
	postId := strurl[13:]
	post_id, _ := strconv.Atoi(postId)
	userId := r.Header.Get("id")
	user_id, err := strconv.Atoi(userId)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}
	post, err := app.models.Posts.Get(int64(post_id))
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}
	if user_id != post.UserID {
		app.errorResponse(w, r, 211, "you cant delete this post because youre not author")
		return
	}
	err = app.models.Posts.Delete(int64(post_id))
	if err != nil {
		app.serverErrorResponse(w, r, err)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
