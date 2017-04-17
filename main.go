package main

import (
	"database/sql"
	_"github.com/go-sql-driver/mysql"
	"net/http"
	"crypto/sha256"
	"encoding/hex"
	"text/template"
)


// Connect to database 
func getDBConnection() (*sql.DB, error) {
	db, err := sql.Open("mysql", "root:kunal@/authDB")
	return db, err
}

// Login route
func login(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.ServeFile(w, req, "login.html")
		return
	}
	
	// Set login data from login.html file
	email := req.FormValue("email")
	password:= req.FormValue("password")
	pwd := sha256.Sum256([]byte(password))
	foundUser := email
	var dbemail string
	db,err:= getDBConnection()
	if err == nil{
		defer db.Close()
		
		//Database query
		err:= db.QueryRow("SELECT email FROM users WHERE email=? AND password=?",email,hex.EncodeToString(pwd[:])).Scan(&dbemail)
		if err == nil {
			w.Write([]byte("hello user"))
			w.Write([]byte(dbemail))
		}else {
			http.Redirect(w, req,"/app3/login",301)
			return
		}
	}

}


// Register route
func register(w http.ResponseWriter, req *http.Request) {

	if req.Method != "POST" {
		http.ServeFile(w, req, "register.html")
		return
	}

	email:= req.FormValue("email")
	password:= req.FormValue("password")
	
	// Encrypt password
	pwd := sha256.Sum256([]byte(password))
	//w.Write([]byte(pwd))



	//var user string
	db,err:= getDBConnection()
	//err= db.QueryRow("SELECT email FROM users WHERE email=?",email).Scan(&user)

	if err == nil {
		defer db.Close()
		_,err = db.Exec("INSERT INTO users(email,password) VALUES(?,?)",email,hex.EncodeToString(pwd[:]))

		if err == nil {
			http.Redirect(w,req,"/app3/profile",301)
		}else {
			//http.Error(w,"Cant create",500)
			http.Redirect(w,req,"/app3/",301)

		}
		w.Write([]byte("User created"))

	}
}


// Create profile route
func createProfile(w http.ResponseWriter,req *http.Request) {
	if req.Method != "POST" {
		http.ServeFile(w, req, "profile.html")
		return
	}
	email:= req.FormValue("email")
	FirstName := req.FormValue("fname")
	LastName := req.FormValue("lname")
	Address := req.FormValue("address")
	number := req.FormValue("cnumber")
	db,err:= getDBConnection()

	if err == nil {
		_,err := db.Exec("UPDATE users SET fname=?,lname=?,address=?,number=? WHERE email=?",
		FirstName,LastName,Address,number,email)
		if err==nil{
			w.Write([]byte("values updated"))
		}else {
			w.Write([]byte("error"))
		}
	}

}



func getProfile(w http.ResponseWriter,req *http.Request){
	w.Header().Add("Content Type","text/html")
	tmpl,err := template.New("profile").Parse(doc)
	if err == nil{
		tmpl.Execute(w,foundUser)
	}
	
}
const doc = `
<html>
<body>
	works
	{{.}}
</body>
</html>
`

func main()  {
	db,err := getDBConnection()
	if err != nil {
		panic(err.Error())
	}
	//defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err.Error())
	}

	http.HandleFunc("/app3/register",register)
	http.HandleFunc("/app3/",login)
	http.HandleFunc("/app3/profile",createProfile)
	http.ListenAndServe(":8011",nil)
}

