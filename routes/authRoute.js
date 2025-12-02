import { Router } from "express";
import { login, register, refreshToken } from "../controller/authController.js";

const authRouter = Router();

authRouter.post("/register", register);
authRouter.post("/login", login);
authRouter.post("/refresh", refreshToken);

export default authRouter;
