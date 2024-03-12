const express = require("express");
const mysql = require("mysql2");
const dotenv = require("dotenv");
const path = require("path");
const bcrypt = require("bcryptjs");

const app = express();
app.set('view engine', 'hbs')
dotenv.config({path: "./.env"});

const publicDir = path.join(__dirname, './webbsidan')

const saltRounds = 10
const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/; //Lånad från stackoverflow
const passwordRegex = /^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,}$/; //Lånad från stackowerflow


encrypt = (data) => {
    bcrypt.hash(data, saltRounds, function(err, hash) {console.log(hash, "hash"); return hash});
}

const db = mysql.createConnection({
    // värden hämtas från .env
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE
});

app.use(express.urlencoded({extended: 'false'}))
app.use(express.json())

db.connect((error) => {
    if(error){
        console.log(error);
    } else{
        console.log("Ansluten till MySQL");
    }
});

// Använder mallen index.hbs
app.get("/", (req, res) => {
    res.render("index");
});

// Använder mallen register.hbs
app.get("/register", (req, res) => {
    res.render("register");
});

// Använder mallen login.hbs
app.get("/login", (req, res) => {
    res.render("login");
});

// Tar emot poster från registeringsformuläret
app.post("/auth/register", (req, res) => {  
    const { name, email, password, password_confirm } = req.body

    //Försöker hämta hem användernamnet och eposten från databasen. Om den lyckas skickas ett felmeddelande till clitenten eftersom anvädarnamnet är i bruk
    db.query("SELECT * FROM users", function (err, result, fields) {
        if (err) throw err;
        if (result.find(user => user.name === name) || result.find(user => user.email === email)) return res.render('register', {
            message: 'Användarnamn eller epost i bruk'
        })
    })

    //Kollar så att de båda lösenorden matchar
    if (password != password_confirm) res.render('register', {message: 'Fel lösenord'})

    //Kollar så att emailen matchar regexen 
    if (!email.match(emailRegex)) res.render('register', {message: 'Eposten är felaktig'})

    //Kollar så att lösenordet matchar regexen
    if (!password.match(passwordRegex)) res.render('register', {message: 'Lösenordet måste innehålla minst 8 bokstäver, 1 stor bokstav, 1 siffra och ett tecken'})

    //Krypterar lösenordet i inserten
    /*db.query('INSERT INTO users SET?', {name: name, email: email, password: bcrypt.hashSync(password, saltRounds)   }, (err, result) => {
            if(err) {
                console.log(err)
            } else {
                return res.render('register', {
                    message: 'Användare registrerad'
                })
            }       
    })*/
})

// Tar emot poster från loginsidan
app.post("/auth/login", (req, res) => {   
    const { name, password } = req.body

    db.query('SELECT name, password FROM users WHERE name = ?', [name], async (error, result) => {
        if(error){
            console.log(error)
        }
        // Om == 0 så finns inte användaren
        if( result.length == 0 ) {
            return res.render('login', {
                message: "Användaren finns ej"
            })

        } else {

            // Vi kollar om lösenordet som är angivet matchar det i databasen
            if (bcrypt.compareSync(password, result[0].password)) {
                return res.render('login', {
                    message: "Du är nu inloggad"
                })
           } 
           else {
                return res.render('login', {
                    message: "Fel lösenord"
                })
           }
        }
    })
})

// Körde på 4k här bara för att skilja mig åt
// från server.js vi tidigare kört som använder 3k
app.listen(3000, ()=> {
    console.log("Servern körs, besök http://localhost:3000")
})