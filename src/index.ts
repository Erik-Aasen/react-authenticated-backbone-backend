import mongoose, { Error } from 'mongoose';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import passport from 'passport';
import passportLocal from 'passport-local';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import User from './User';
import dotenv from 'dotenv';
import { UserInterface, DatabaseUserInterface } from './Interfaces/UserInterface';

const LocalStrategy = passportLocal.Strategy;
dotenv.config();

mongoose.connect(`${process.env.PART1}${process.env.USERNAME}:${process.env.PASSWORD}${process.env.PART2}`, {
  useCreateIndex: true,
  useNewUrlParser: true,
  useUnifiedTopology: true
}, (err: Error) => {
  if (err) throw err;
  console.log("Connected to Mongo");
});

// Middleware
const app = express();
app.use(express.json());
app.use(cors({ origin: "https://festive-meitner-2ae6d5.netlify.app", credentials: true }))

app.set("trust proxy", 1);

app.use(
  session({
    secret: `${process.env.SESSIONSECRET}`,
    resave: true,
    saveUninitialized: true,
    cookie: {
      sameSite: "none",
      secure: true,
      maxAge: 1000 * 60 * 5 // 5 minutes
    }
  })
);

app.use(cookieParser());
app.use(passport.initialize());
app.use(passport.session());

//Passport
passport.use(new LocalStrategy((username: string, password: string, done) => {
  User.findOne({ username: username }, (err: Error, user: DatabaseUserInterface) => {
    if (err) throw err;
    if (!user) return done(null, false);
    bcrypt.compare(password, user.password, (err: Error, result: boolean) => {
      if (err) throw err;
      if (result === true) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    });
  });
})
);

passport.serializeUser((user: DatabaseUserInterface, cb) => {
  cb(null, user._id);
});

passport.deserializeUser((id: string, cb) => {
  User.findOne({ _id: id }, (err: Error, user: DatabaseUserInterface) => {
    const userInformation: UserInterface = {
      id: user._id,
      username: user.username,
      isAdmin: user.isAdmin
    };
    cb(err, userInformation);
  });
});

// Routes
app.post('/register', async (req: Request, res: Response) => {

  const { username, password } = req.body;
  if (!username || !password || typeof username !== "string" || typeof password !== "string") {
    res.send("Improper values")
    return;
  }

  User.findOne({ username }, async (err: Error, doc: DatabaseUserInterface) => {
    if (err) throw err;
    if (doc) res.send("User already exists");
    if (!doc) {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      const newUser = new User({
        username,
        password: hashedPassword
      });
      await newUser.save();
      res.send("registered")
    }
  })
})

const isAdministratorMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const { user }: any = req;
  if (user) {
    User.findOne({ username: user.username }, (err: Error, user: DatabaseUserInterface) => {
      if (err) throw err;
      if (user?.isAdmin) {
        next()
      } else {
        res.send("Sorry, only admins can perform this")
      }
    })
  } else {
    res.send("Sorry, you arent logged in")
  }
}

app.post("/login", passport.authenticate("local"), (req, res) => {
  res.send("logged in");
})

app.get("/logout", (req, res) => {
  req.logout();
  res.send("logged out");
})

app.get("/user", (req, res) => {
  res.send(req.user);
  console.log(req.user);
  
})

app.post("/deleteuser", isAdministratorMiddleware, async (req, res) => {
  const { id } = req?.body
  await User.findByIdAndDelete(id)
    .catch((err: Error) => { throw err });
  res.send("user deleted")
});

app.get("/getallusers", isAdministratorMiddleware, async (req, res) => {
  await User.find({}, (err: Error, data: DatabaseUserInterface[]) => {
    if (err) throw err;
    const filteredUsers : UserInterface[] = [];
    data.forEach((item : DatabaseUserInterface) => {
      const userInformation = {
        id: item._id,
        username: item.username,
        isAdmin: item.isAdmin
      }
      filteredUsers.push(userInformation);
    })
    res.send(filteredUsers)
  })
})

app.listen(process.env.PORT || 4000, () => {
  console.log("Server Started");
})