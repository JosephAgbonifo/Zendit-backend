import jwt from "jsonwebtoken";

export const auth = (req, res, next) => {
  const token = req.cookies.accessToken;

  if (!token) {
    return res.status(401).json({ error: "Not logged in" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }

    req.user = {
      id: user.id,
      email: user.email,
      username: user.username
    };

    next();
  });
};
