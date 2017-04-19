package main

import (
	"database/sql"
	_"github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"net/http"
	"crypto/sha256"
	"encoding/hex"
	"github.com/gorilla/context"
	"fmt"
	"html/template"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2/google"
	"net/url"
	"strings"
	"encoding/json"
)
var store = sessions.NewCookieStore([]byte("Secret text"))
var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

type user struct {
	Email string
	Fname string
	Lname string
	Address string
	Number string
}

//struct for received api from google login in JSON format
type googleapi struct {
	Id string `json:"id"`
	Email string `json:"email"`
	Fname string `json:"given_name"`
	Lname string `json:"family_name"`
}

//google api connection details
var (
	oauthConf = &oauth2.Config{
		ClientID:     "1087348076225-rbk3ndq903oooe11bkjev8uuhqos310d.apps.googleusercontent.com",
		ClientSecret: "ChvX484B3EEwJ2cjspq0ZA4L",
		RedirectURL:  "http://localhost:8011/google/back",
		//Scopes:       []string{"https://www.googleapis.com/auth/plus.login"},
		Scopes:[]string{"profile","email"},
		Endpoint:     google.Endpoint,
	}
	oauthStateString = "Secret String"
)

//Login with google
func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	Url, err := url.Parse(oauthConf.Endpoint.AuthURL)
	if err != nil {
		log.Fatal("Parse: ", err)
	}
	parameters := url.Values{}
	parameters.Add("client_id", oauthConf.ClientID)
	parameters.Add("scope", strings.Join(oauthConf.Scopes, " "))
	parameters.Add("redirect_uri", oauthConf.RedirectURL)
	parameters.Add("response_type", "code")
	parameters.Add("state", oauthStateString)
	Url.RawQuery = parameters.Encode()
	url := Url.String()
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Call back for login with google
func handleGoogleCallback(w http.ResponseWriter, req *http.Request) {
	var id string
	var email string
	var fname string
	var lname string
	var sessId int
	state := req.FormValue("state")
	if state != oauthStateString {
		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(w, req, "/", http.StatusTemporaryRedirect)
		return
	}

	code := req.FormValue("code")

	token, err := oauthConf.Exchange(oauth2.NoContext, code)
	if err != nil {
		fmt.Printf("oauthConf.Exchange() failed with '%s'\n", err)
		http.Redirect(w, req, "/showprofile", http.StatusTemporaryRedirect)
		return
	}

	resp,err:=  http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)

	if err != nil {
		fmt.Printf("Get: %s\n", err)
		http.Redirect(w, req, "/showprofile", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()

	response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("ReadAll: %s\n", err)
		http.Redirect(w, req, "/showprofile", http.StatusTemporaryRedirect)
		return
	}
	var api googleapi
// converting parsed data received from google
	new:= json.Unmarshal(response,&api)
	if new == nil {

	}

	id= api.Id
	email = api.Email
	fname = api.Fname
	lname = api.Lname
	db,err:= getDBConnection()
	if err == nil {
		defer db.Close()
		// Check if user has already registered?
		// If yes then store account id to sessIF
		err = db.QueryRow("SELECT id from users where googleid=?",id).Scan(&sessId)
		fmt.Println(sessId)
		if sessId!=0{
			// If already registered, create session and store ID in session
			session,err:= store.Get(req,"session-name")
			if err == nil {
				fmt.Println("session id")
				fmt.Println(sessId)
				session.Values["userid"] = sessId
				session.Save(req,w)
				http.Redirect(w, req, "/profile", 301)
			}else {
				fmt.Println("ERROR")
			}
		}else{
			//If user is not registered, insert user details in database
				_,err := db.Exec("INSERT into users(googleid,email,fname,lname) values(?,?,?,?)",id,email,fname,lname)
				if err == nil {
					session,err:= store.Get(req,"session-name")
					if err == nil {
						//store id in session
						db.QueryRow("Select id from users where googleid=?",id).Scan(&sessId)
						session.Values["userid"] = id
						session.Save(req,w)
						http.Redirect(w, req, "/profile", 301)
					}
				}
			}
		}


	log.Printf("parseResponseBody: %s\n", string(response))

	http.Redirect(w, req, "/profile", http.StatusTemporaryRedirect)
}


func getDBConnection() (*sql.DB, error) {
	db, err := sql.Open("mysql", "root:kunal@/authDB")
	return db, err
}

//Clear session
func clearSession(w http.ResponseWriter)  {
	cookie := &http.Cookie{
		Name: "session-name",
		Value: "session-name",
		Path: "/",
		MaxAge: -1,
	}
	http.SetCookie(w,cookie)
}

//clear session on logout
func logout(w http.ResponseWriter, req *http.Request)  {
	clearSession(w)
	http.Redirect(w,req,"/",301)
}

func login(w http.ResponseWriter, req *http.Request) {
	// If method = get then server login.html
	if req.Method != "POST" {
		http.ServeFile(w, req, "login.html")
		return
	}
	email := req.FormValue("email")
	password:= req.FormValue("password")
	// encrypt password to sha256
	pwd := sha256.Sum256([]byte(password))
	var dbemail string
	var dbid int
	db,err:= getDBConnection()
	if err == nil{
		defer db.Close()

		err:= db.QueryRow("SELECT id,email FROM users WHERE email=? AND password=?",email,hex.EncodeToString(pwd[:])).Scan(&dbid,&dbemail)
		if err == nil {
			//store id in session
			session,err:= store.Get(req,"session-name")
			if err == nil {
				session.Values["userid"] = dbid
				session.Save(req,w)
				http.Redirect(w,req,"/showprofile",301)

			}else {
			}

		}else {
			w.Write([]byte("User does not exist. Please register."))
			http.Redirect(w, req,"/login",301)
			return
		}
	}

}


func register(w http.ResponseWriter, req *http.Request) {

	if req.Method != "POST" {
		http.ServeFile(w, req, "register.html")
		return
	}
	var temp_usr string
	var id int

	email:= req.FormValue("email")
	password:= req.FormValue("password")
	pwd := sha256.Sum256([]byte(password))
	db,err:= getDBConnection()

	if err == nil {
		defer db.Close()
		//check if user with same email already exist ?
		err = db.QueryRow("SELECT email from users where email=?",email).Scan(&temp_usr)
		if err == nil{
			w.Write([]byte("User with this email already exist. Please enter another email"))
		}else {
			//If not then create new user with input details
			_, err = db.Exec("INSERT INTO users(email,password) VALUES(?,?)", email, hex.EncodeToString(pwd[:]))

			if err == nil {
				err = db.QueryRow("SELECT id from users where email=?",email).Scan(&id)
				session,err:= store.Get(req,"session-name")
				if err == nil {
					session.Values["userid"] = id
					session.Save(req,w)
					http.Redirect(w, req, "/profile", 301)
				}
			} else {
				//http.Error(w,"Cant create",500)
				http.Redirect(w, req, "/", 301)

			}
			w.Write([]byte("User created"))
		}

	}
}

//Get profile with user data
func getProfile(w http.ResponseWriter, req *http.Request){
	var email string
	var fname string
	var lname string
	var address string
	var number string
	session,err := store.Get(req,"session-name")
	if err != nil {
		w.Write([]byte("Error creating session"))
	}
	db,err:= getDBConnection()
	if err == nil {

	err:= db.QueryRow("SELECT email,fname,lname,address,number FROM users WHERE id=?",
		session.Values["userid"]).Scan(&email,&fname,&lname,&address,&number)
		fmt.Println("sesion id is")
		fmt.Println(session.Values["userid"])
		if err == nil{
		tpl,err := template.ParseFiles("usrprofile.html")
		if err == nil {
			tpl.Execute(w, user{email,fname,lname,address,number})
			}else {
			w.Write([]byte("Error"))

		}
	}else {
			w.Write([]byte("Please login"))
		}
	}
}
func createProfile(w http.ResponseWriter,req *http.Request) {
	if req.Method != "POST" {
		http.ServeFile(w, req, "profile.html")
		return
	}
	session,err := store.Get(req,"session-name")
	if err == nil {
		val := session.Values["userid"]
		fmt.Println(val)
	}
	FirstName := req.FormValue("fname")
	LastName := req.FormValue("lname")
	Address := req.FormValue("address")
	number := req.FormValue("cnumber")
	db,err:= getDBConnection()

	if err == nil {
		_,err := db.Exec("UPDATE users SET fname=?,lname=?,address=?,number=? WHERE id=?",
		FirstName,LastName,Address,number,session.Values["userid"])
		if err==nil{
			http.Redirect(w, req,"/showprofile",301)
		}else {
			w.Write([]byte("error editing your profile"))
		}
	}

}


func main()  {
	//var store = sessions.NewCookieStore([]byte("Secret text"))
	db,err := getDBConnection()
	if err != nil {
		panic(err.Error())
	}
	//defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err.Error())
	}

	http.HandleFunc("/register",register)
	http.HandleFunc("/",login)
	http.HandleFunc("/login",login)
	http.HandleFunc("/profile",createProfile)
	http.HandleFunc("/showprofile",getProfile)
	http.HandleFunc("/login/google", handleGoogleLogin)
	http.HandleFunc("/google/back",handleGoogleCallback)
	http.HandleFunc("/logout",logout)
	http.ListenAndServe(":8011",context.ClearHandler(http.DefaultServeMux))
}

