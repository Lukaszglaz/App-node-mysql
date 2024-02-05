const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { promisify } = require("util");
const { log } = require("console");
const transporter = require("../controllers/nodemailer");
const crypto = require("crypto");
const speakeasy = require("speakeasy");
const base32 = require("thirty-two");

const db = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE,
});

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).render("login", {
        message: "Please provide an email and password",
      });
    }

    db.query(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (error, results) => {
        console.log(results);
        if (
          !results ||
          !(await bcrypt.compare(password, results[0].password))
        ) {
          res.status(401).render("login", {
            message: "Email or Password is incorrect",
          });
        } else {
          const id = results[0].id;

          const token = jwt.sign({ id }, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRES_IN,
          });

          console.log("The token is:" + token);

          const cookieOptions = {
            expires: new Date(
              Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
            ),
            httpOnly: true,
          };

          res.cookie("jwt", token, cookieOptions);
          res.status(200).redirect("/");
        }
      }
    );
  } catch (error) {
    console.log(error);
  }
};

exports.register = (req, res) => {
  console.log(req.body);

  const { name, email, password, passwordConfirm } = req.body;

  db.query(
    "SELECT email FROM users WHERE email = ?",
    [email],
    async (error, results) => {
      if (error) {
        console.log(error);
      }
      if (results.length > 0) {
        return res.render("register", {
          message: "That email is already in use",
        });
      } else if (password !== passwordConfirm) {
        return res.render("register", {
          message: "Password do not match",
        });
      }

      let hashedPassword = await bcrypt.hash(password, 8);
      console.log(hashedPassword);

      db.query(
        "INSERT INTO users SET ? ",
        { name: name, email: email, password: hashedPassword },
        (error, results) => {
          if (error) {
            console.log(error);
          } else {
            const mailOptions = {
              from: "kontakt@glazlukasz.pl",
              to: email,
              subject: "| glazlukasz.pl | Dziękujemy za rejestrację!",
              html: `
                              <!DOCTYPE html>
                <html>
                  <head>
                    <style>
                      body {
                        font-family: Arial, sans-serif;
                        background-color: #f2f2f2;
                        margin: 0;
                        padding: 0;
                      }

                      .container {
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                        background-color: #ffffff;
                      }

                      h1 {
                        color: #1cd4e2;
                        font-size: 28px;
                        text-align: right;
                      }

                      h3 {
                        font-size: 18px;
                        margin-top: 15px;
                      }

                      h2,
                      h3 {
                        color: #000000;
                      }

                      h4,
                      h5 {
                        margin: 0;
                        margin-top: 7px;
                        font-size: 15px;
                      }

                      ul {
                        list-style-type: disc;
                        margin-left: 15px;
                      }

                      .text-under {
                        text-align: center;
                        font-size: 12px;
                      }

                      .footer {
                        background-color: #f2f2f2;
                        padding: 7px 0;
                      }

                      .copyright {
                        color: #000000;
                        text-align: center;
                        padding: 10px;
                      }

                      .container-two p {
                        margin: 0;
                        margin-top: 15px;
                        margin-bottom: 15px;
                        font-size: 15px;
                      }

                      a {
                        text-decoration: none;
                      }
                    </style>
                  </head>

                  <body>
                    <div class="container">
                      <h1>glazlukasz</h1>
                      <hr />
                      <h3>Dzień Dobry,</h3>
                      <div class="container-two">
                        <p>
                          Dziękujemy za rejestrację w naszej aplikacji
                          <a href="https://applog.glazlukasz.pl" target="_blank"
                            >applog.glazlukasz.pl</a
                          >. Cieszymy się, że jesteś częścią naszej społeczności.
                        </p>

                        <p>
                          Nasz zespół wsparcia technicznego glazlukasz.pl jest dostępny, aby
                          pomóc Ci w razie problemów z aplikacją lub logowaniem. Prosimy o
                          kontakt na adres e-mailowy:
                          <a href="mailto:kontakt@glazlukasz.pl">kontakt@glazlukasz.pl</a>.
                        </p>

                        <p>
                          Twoje zgłoszenie jest ważne dla nas, i chcemy zapewnić Ci jak
                          najszybszą i najbardziej satysfakcjonującą pomoc.
                        </p>
                        <hr />
                        <p>
                          Dziękujemy za wybór naszego serwisu glazlukasz i za to, że jesteś
                          częścią naszej społeczności. Nasz rozwijający się zespół nieustannie
                          pracuje nad doskonaleniem naszej strony internetowej i ceni sobie
                          Twoją opinię.
                        </p>
                      </div>
                      <h4>Z poważaniem,</h4>
                      <h5>Zespół glazlukasz</h5>

                      <hr />
                      <p class="text-under" style="margin-top: 20px">
                        Chcielibyśmy poinformować, że ta wiadomość email została wygenerowana
                        automatycznie przez nasz system. Prosimy więc o nieodpowiadanie na tą
                        wiadomość e-mail.
                      </p>

                      <p class="text-under">
                        W związku z wysyłanymi przez nas wiadomościami e-mail, pragniemy zwrócić
                        uwagę na kwestię praw autorskich. Treść wiadomości oraz wszelkie
                        załączniki stanowią naszą własność intelektualną i są chronione
                        przepisami prawa autorskiego. Ochrona ta obejmuje m.in. zakaz
                        kopiowania, rozpowszechniania oraz wykorzystywania tych treści w celach
                        komercyjnych bez naszej zgody.
                      </p>
                    </div>
                    <div class="footer">
                      <p class="copyright">© 2024 glazlukasz.pl. Wszelkie prawa zastrzeżone.</p>
                    </div>
                  </body>
                </html>
              `,
            };

            transporter.sendMail(mailOptions, (error, info) => {
              if (error) {
                console.error(error);
              } else {
                console.log("E-mail wysłany: " + info.response);
              }
            });

            console.log(results);
            return res.render("register", {
              message: "User registered",
            });
          }
        }
      );
    }
  );
};

exports.isLoggedIn = async (req, res, next) => {
  req.message = "Inside middleware";

  // console.log(req.cookies);
  if (req.cookies.jwt) {
    try {
      // 1) Verify the token
      const decoded = await promisify(jwt.verify)(
        req.cookies.jwt,
        process.env.JWT_SECRET
      );

      console.log(decoded);

      // 2) Check if the user still exists
      db.query(
        "SELECT * FROM users WHERE id = ?",
        [decoded.id],
        (error, result) => {
          console.log(result);

          if (!result) {
            return next();
          }

          req.user = result[0];
          return next();
        }
      );
    } catch (error) {
      console.log(error);
      return next();
    }
  } else {
    next();
  }
};

exports.logout = async (req, res) => {
  res.cookie("jwt", "logout", {
    expires: new Date(Date.now() + 2 * 1000),
    httpOnly: true,
  });

  res.status(200).redirect("/");
};

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    // Sprawdzenie, czy adres e-mail istnieje w bazie danych
    const checkEmailQuery = `SELECT name FROM users WHERE email = ?`;
    db.query(checkEmailQuery, [email], (checkEmailErr, result) => {
      if (checkEmailErr) {
        console.error("Błąd podczas sprawdzania adresu e-mail:", checkEmailErr);
        res.status(500);
        res.render("error", { errorMessage: "Wystąpił błąd serwera" });
        return;
      }

      if (result.length === 0) {
        // Adres e-mail nie istnieje w bazie danych
        res.status(400);
        res.render("error", {
          errorMessage: "Podany adres e-mail nie należy do żadnego konta",
        });
        return;
      }

      // Adres e-mail istnieje, pobierz nazwę użytkownika
      const userName = result[0].name;

      // Generuj token, kod dwuczłonowy itp.
      const token = crypto.randomBytes(20).toString("hex");
      const secret = speakeasy.generateSecret({ length: 10 });
      const code = speakeasy.totp({
        secret: base32.encode(secret.base32),
        encoding: "base32",
        step: 600,
      });

      // Aktualizacja bazy danych
      const updateQuery = `UPDATE users SET reset_token = ?, two_factor_code = ? WHERE email = ?`;
      db.query(updateQuery, [token, code, email], (updateErr) => {
        if (updateErr) {
          console.error("Błąd podczas aktualizacji bazy danych:", updateErr);
          res.status(500);
          res.render("error", { errorMessage: "Wystąpił błąd serwera" });
          return;
        }

        // Wysyłanie maila z linkiem do resetowania hasła
        const resetLink = `http://localhost:3000/reset-password/${token}`;
        const mailOptions = {
          from: "kontakt@glazlukasz.pl",
          to: email,
          subject: "| glazlukasz.pl | Resetowanie hasła",
          html: `
              <!DOCTYPE html>
              <html>
                <head>
                  <style>
                    body {
                      font-family: Arial, sans-serif;
                      background-color: #f2f2f2;
                      margin: 0;
                      padding: 0;
                    }
          
                    .container {
                      max-width: 600px;
                      margin: 0 auto;
                      padding: 20px;
                      background-color: #ffffff;
                    }
          
                    h1 {
                      color: #1cd4e2;
                      font-size: 28px;
                      text-align: right;
                    }
          
                    h3 {
                      font-size: 18px;
                      margin-top: 15px;
                    }
          
                    h2,
                    h3 {
                      color: #000000;
                    }
          
                    h4,
                    h5 {
                      margin: 0;
                      margin-top: 7px;
                      font-size: 15px;
                    }
          
                    ul {
                      list-style-type: disc;
                      margin-left: 15px;
                    }
          
                    .text-under {
                      text-align: center;
                      font-size: 12px;
                    }
          
                    .footer {
                      background-color: #f2f2f2;
                      padding: 7px 0;
                    }
          
                    .copyright {
                      color: #000000;
                      text-align: center;
                      padding: 10px;
                    }
          
                    .container-two p {
                      margin: 0;
                      margin-top: 15px;
                      margin-bottom: 15px;
                      font-size: 15px;
                    }
          
                    a {
                      text-decoration: none;
                    }
                    p {
                      color: #000000;
                    }
                  </style>
                </head>
          
                <body>
                  <div class="container">
                    <h1>glazlukasz</h1>
                    <hr />
                    <h3>Dzień Dobry, ${userName}</h3>
                    <div class="container-two">
    
                    <p > Otrzymujesz tę wiadomość, ponieważ wysłałeś prośbę o zresetowanie hasła w naszej aplikacji. </p>
    
                      <p>
                        Aby zresetować hasło, kliknij ten link: <a href="${resetLink}">${resetLink}</a>
                      </p>
          
                      <p>
                        Twój kod autoryzujący zresetowanie hasła to: <strong>${code}</strong>
                      </p>
    
                      <p> Twój kod autoryzujący zresetowanie hasła jest ważny przez 10 minut. Po upływie tego czasu będziesz musiał(a) ponownie zresetować hasło. </p>
                    </div>
                    <hr />
                    <p class="text-under" style="margin-top: 20px">
                      Chcielibyśmy poinformować, że ta wiadomość email została wygenerowana
                      automatycznie przez nasz system. Prosimy więc o nieodpowiadanie na tą
                      wiadomość e-mail.
                    </p>
          
                    <p class="text-under">
                      W związku z wysyłanymi przez nas wiadomościami e-mail, pragniemy zwrócić
                      uwagę na kwestię praw autorskich. Treść wiadomości oraz wszelkie
                      załączniki stanowią naszą własność intelektualną i są chronione
                      przepisami prawa autorskiego. Ochrona ta obejmuje m.in. zakaz
                      kopiowania, rozpowszechniania oraz wykorzystywania tych treści w celach
                      komercyjnych bez naszej zgody.
                    </p>
                  </div>
                  <div class="footer">
                    <p class="copyright">© 2024 glazlukasz.pl. Wszelkie prawa zastrzeżone.</p>
                  </div>
                </body>
              </html>
            `,
        };

        transporter.sendMail(mailOptions, (mailErr, info) => {
          if (mailErr) {
            console.error("Błąd podczas wysyłania maila:", mailErr);
            res.status(500);
            res.render("error", { errorMessage: "Wystąpił błąd serwera" });
          } else {
            console.log("Mail wysłany:", info.response);
            res.status(200);
            res.render("success", {
              successMessage:
                "Dane do zresetowania hasła zostały wysłane na podany adres email",
            });
          }
        });
      });
    });
  } catch (error) {
    console.log(error);
    res.status(500);
    res.render("error", { errorMessage: "Wystąpił błąd serwera" });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { password, confirmPassword, resetToken, authCode } = req.body;

    console.log("Received reset request:", {
      password,
      confirmPassword,
      resetToken,
      authCode,
    });

    // Sprawdź, czy kod autoryzacyjny jest poprawny
    const query = `SELECT * FROM users WHERE reset_token = ? AND two_factor_code = ?`;
    db.query(query, [resetToken, authCode[0]], (err, results) => {
      if (err) {
        console.error("Błąd podczas sprawdzania kodu autoryzacyjnego:", err);
        res.status(500);
        res.render("error", { errorMessage: "Wystąpił błąd serwera" });
      } else {
        console.log("Wyniki zapytania do bazy danych:", results);
        if (results.length === 0) {
          // Jeśli kod autoryzacyjny jest niepoprawny
          console.log("Nieprawidłowy kod autoryzacyjny");
          res.status(401);
          res.render("error", {
            errorMessage: "Nieprawidłowy kod autoryzacyjny",
          });
        } else {
          // Jeśli kod autoryzacyjny jest poprawny, sprawdź zgodność haseł
          if (password !== confirmPassword) {
            // Jeśli hasła nie są zgodne
            console.log("Hasła nie są ze sobą zgodne");
            res.status(400);
            res.render("error", { errorMessage: "Hasła nie są zgodne" });
          } else {
            // Jeśli hasła są zgodne, zaktualizuj hasło
            const hashedPassword = bcrypt.hashSync(password, 10);
            const updateQuery = `UPDATE users SET password = ?, reset_token = NULL, two_factor_code = NULL WHERE reset_token = ?`;

            db.query(updateQuery, [hashedPassword, resetToken], (updateErr) => {
              if (updateErr) {
                console.error("Błąd podczas aktualizacji hasła:", updateErr);
                res.status(500);
                res.render("error", { errorMessage: "Wystąpił błąd serwera" });
              } else {
                console.log("Hasło zresetowane pomyślnie");
                res.status(200);
                res.render("success", {
                  successMessage: "Hasło zresetowane pomyślnie",
                });
              }
            });
          }
        }
      }
    });
  } catch (error) {
    console.log(error);
    res.status(500);
    res.render("error", { errorMessage: "Wystąpił błąd serwera" });
  }
};

exports.resetPasswordPage = (req, res) => {
  const { token: resetToken } = req.params;
  console.log("Reset Token from Params:", resetToken);
  console.log("Reset Token from Request Object:", req.params.resetToken);
  console.log("Reset Token from URL:", req.url);
  console.log("Request Params:", req.params);
  res.render("reset-password-page", { resetToken: resetToken });
};
