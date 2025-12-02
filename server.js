import express from "express";
import { configDotenv } from "dotenv";
import cors from "cors";
import authRouter from "./routes/authRoute.js";

configDotenv();

const port = process.env.PORT

const app = express();

app.get("/", (req, res) => {
    res.json({"message":"Zendit server running"})
})

app.get("/health", (req, res)=>{
    res.json({"message":"server is healthy"})
})

app.use("/auth", authRouter)

app.listen(port, () => {
    console.log(`app is listening on  port ${port}`)
})