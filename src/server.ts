import express from "express";
import { usersRouter } from "./routes/users";
import { filesRouter } from "./routes/files";
import { adminRouter } from "./routes/admin";

const app = express();
app.use(express.json());

app.use("/users", usersRouter);
app.use("/files", filesRouter);
app.use("/admin", adminRouter);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Vulnerable demo app listening on port ${PORT}`);
});
