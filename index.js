const express = require("express");
const mongoose = require("mongoose")
const { request } = require("http");
const path = require("path");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken"); 
const bcrypt = require("bcrypt");   

mongoose.connect("mongodb://127.0.0.1:27017",{
    dbName:"backend"
}).then(()=> console.log("Connected to database"))
.catch((e)=>console.log(e));

const formSchema = new mongoose.Schema({
    name:String,
    email:String,
    password:String,
})

const form = mongoose.model("Message", formSchema)

const app = express();

//using middlewares
app.use(express.static(path.join(path.resolve(), "public")))
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());

//setting up view engine
app.set("view engine", "ejs")

const isAuthenticated = async (req, res, next)=>{
    const{token} = req.cookies;
    if (token){
        const decoded = jwt.verify(token, "askaiarhnas");
        
        req.form = await form.findById(decoded._id);

        next();
    }else{
        res.redirect("login");
    }
};

app.get("/",isAuthenticated,(req, res)=>{
    // console.log(req.form);
    res.render("logout", {name : req.form.name})
})

app.get("/register",(req, res)=>{
    res.render("register")
})

app.get("/login",(req, res)=>{
    res.render("login")
})

app.post("/login",async (req,res)=>{
    const{email, password} = req.body;

    let user = await form.findOne({email})

    if(!user)return res.redirect("/register")

    const isMatch = await bcrypt.compare(password, user.password) 

    if(!isMatch) return res.render("login",{email, message:"! Incorrect Password"})

    const token = jwt.sign({_id:user._id}, "askaiarhnas");

    res.cookie("token", token,{
        httpOnly:true,
        expires: new Date(Date.now()+60*1000)
    })
    res.redirect("/")
})

app.post("/register",async (req,res)=>{
    const {name, email, password} = req.body;

    let user = await form.findOne({email})
    if(user){
        return res.redirect("/login")
    }

    //hashing users password for security
    const hashedPassword = await bcrypt.hash(password,10);

     user = await form.create({
        name,
        email,
        password: hashedPassword,
    });

    const token = jwt.sign({_id:user._id}, "askaiarhnas");

    res.cookie("token", token,{
        httpOnly:true,
        expires: new Date(Date.now()+60*1000)
    })
    res.redirect("/")
})

app.get("/logout",(req, res)=>{
    res.cookie("token", null,{
        httpOnly:true,
        expires:new Date(Date.now()),
    })
    res.render("login") 
});

app.listen(5000, ()=>{
    console.log("server is working")
})