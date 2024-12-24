import express from 'express';
import cors from 'cors';
import mysql from 'mysql2'; // Use mysql2
import bcrypt from 'bcrypt';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';
import multer from 'multer';
import path, { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path'
import dotenv from 'dotenv';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import https from 'https';
import cron from 'node-cron';
dotenv.config();
const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const router = express.Router();

app.use('/uploads', express.static(join(__dirname, 'uploads')));
app.use(bodyParser.json());
app.use(cors({
origin: 'https://brandsearning.com',
methods: ['GET','HEAD','PUT','PATCH','POST','DELETE'],  // Added 'PUT' here

credentials: true,

}));
const options = {
  key: fs.readFileSync('/etc/letsencrypt/live/brandsearning.com/privkey.pem'),
  cert: fs.readFileSync('/etc/letsencrypt/live/brandsearning.com/fullchain.pem')
};

app.use(cookieParser());
app.use(express.json());
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true, maxAge: 699900000 }  // secure should be true in production

}));
const PORT=8084;
const con = mysql.createConnection({
    host: '127.0.0.1',
    user: 'user',
    password: 'password',
    database: 'database', 
});

con.connect(function(err){
    if (err) {
        console.error('Error in connection:', err); 
    } else {
        console.log('Connected');
    }
}
);

function keepConnectionAlive() {
    con.query('SELECT 1', (err) => {
      if (err) {
        console.error('Error pinging the database:', err);
      } else {
        console.log('Database connection alive');
      }
    });
  }
  
  setInterval(keepConnectionAlive, 360000);
  


const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
      cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
  });
  const upload = multer({ storage: storage });





  cron.schedule('58 23 * * *', () => {
    console.log('Starting cron job at midnight...');

    con.beginTransaction(err => {
        if (err) {
            console.error('Error starting transaction:', err);
            return;
        }

        const updateWeekAndResetTodayTeamQuery = `
            UPDATE users 
    SET week_team = 0, last_week_team_update = CURDATE()
    WHERE approved = 1 
    AND DATE(last_week_team_update) <= DATE_SUB(CURDATE(), INTERVAL 7 DAY);
        `;
        console.log('Starting update reset of today_team...');
        con.query(updateWeekAndResetTodayTeamQuery, (err, result) => {
            if (err) {
                return con.rollback(() => {
                    console.error('Error resetting today_team:', err);
                });
            }
            console.log('Updated reset today_team for affected users:', result.affectedRows);

            const deleteQuery2 = 'DELETE FROM user_button_clicks';
            console.log('Starting deletion of user_button_clicks...');
            con.query(deleteQuery2, (err2, result2) => {
                if (err2) {
                    return con.rollback(() => {
                        console.error('Error deleting all records from user_button_clicks:', err2);
                    });
                }
                console.log('Deleted all records from user_button_clicks:', result2.affectedRows);

                const deleteOldProductClicksQuery = `
                DELETE FROM user_product_clicks
                WHERE 1;
                `;
                console.log('Starting deletion of old user_product_clicks...');
                con.query(deleteOldProductClicksQuery, (err4, result4) => {
                    if (err4) {
                        return con.rollback(() => {
                            console.error('Error deleting old user_product_clicks:', err4);
                        });
                    }
                    console.log('Deleted old records from user_product_clicks:', result4.affectedRows);

                    con.commit(errCommit => {
                        if (errCommit) {
                            return con.rollback(() => {
                                console.error('Error committing transaction:', errCommit);
                            });
                        }
                        console.log('All database operations completed successfully.');
                    });
                });
            });
        });
    });
});

    

app.post('/payment-crypto', (req, res) => {
    const { trx_id,  id } = req.body;
    const payment_ok = 1;
    const rejected = 0;
    const type=1;

    const checkQuery = 'SELECT COUNT(*) AS count FROM users WHERE trx_id = ?';
    con.query(checkQuery, [trx_id], (checkErr, checkResults) => {
        if (checkErr) {
            return res.status(500).json({ status: 'error', error: 'Database error' });
        }

if (checkResults[0].count > 0) {
    return res.status(400).json({ status: 'error', error: 'Transaction ID already in use' });
  }
  

        const sql = 'UPDATE users SET trx_id = ?,  type = ?, payment_ok = ?, rejected = ? WHERE id = ?';

        con.query(sql, [trx_id, type, payment_ok, rejected, id], (err, result) => {
            if (err) {
                return res.status(500).json({ status: 'error', error: 'Failed to update payment data' });
            }

            res.json({ status: 'success' });
        });
    });
});


const getUserIdFromSession = (req, res, next) => {
    if (req.session && req.session.userId) {
      res.json({ userId: req.session.userId });
    } else {
      res.status(401).json({ error: 'User not authenticated' });
    }
  };
  
  app.get('/getUserIdFromSession', getUserIdFromSession);



  app.get('/', (req, res) => {
    res.send(`
      Welcome to the server!`);

});




app.post('/login', (req, res) => {
    const sql = "SELECT id,email,approved,payment_ok FROM users WHERE email = ? AND password = ?";
    con.query(sql, [req.body.email, req.body.password], (err, result) => {
        if (err) return res.json({Status: "Error", Error: err});

        if (result.length > 0) {
            req.session.userId = result[0].id; 
            req.session.email = result[0].email;
            return res.json({
                Status: "Success",
                Email: req.session.email,
                PaymentOk: result[0].payment_ok,
                id: result[0].id,
                approved: result[0].approved
            });
        } else {
            return res.json({Status: "Error", Error: "Invalid Email/Password"});
        }
    });
});

app.post('/register', (req, res) => {
    try {
        const { ref } = req.query;
        const user = { ...req.body };
        delete user.confirmPassword;

        const checkEmailSql = "SELECT * FROM users WHERE email = ?";
        con.query(checkEmailSql, [user.email], (err, existingUsers) => {
            if (err) {
                return res.json({ status: 'error', error: 'An error occurred while checking the email' });
            }

            if (existingUsers.length > 0) {
                return res.json({ status: 'error', error: 'Email already registered' });
            }

            const registerUser = () => {
                user.refer_by = ref;

                const sql = "INSERT INTO users SET ?";
                con.query(sql, user, (err, result) => {
                    if (err) {
                        console.log(err);
                        return res.json({ status: 'error', error: 'Kindly try again With Referred ID' });
                    }

                    req.session.userId = result.insertId;

                    return res.json({ status: 'success', message: 'User registered successfully', userId: result.insertId });
                });
            };

            if (ref) {
                const checkReferralSql = "SELECT * FROM users WHERE id = ?";
                con.query(checkReferralSql, [ref], (err, referralUsers) => {
                    if (err) {
                        return res.json({ status: 'error', error: 'Failed to check referral ID' });
                    }

                    if (referralUsers.length === 0) {
                        return res.json({ status: 'error', error: 'Please Join With Referred ID' });
                    }

                    registerUser();
                });
            } else {
                registerUser();
            }
        });
    } catch (error) {
        return res.json({ status: 'error', error: 'An unexpected error occurred' });
    }
});




async function registerUser(userData, res) {
    const hashedPassword = await bcrypt.hash(userData.password, 10); 

    const user = {
        ...userData,
        password: hashedPassword
    };

    const sql = "INSERT INTO users SET ?";
    con.query(sql, user, (err, result) => {
        if (err) {
            res.json({status: 'error', error: 'Failed to register user'});
            return;
        }

        res.json({status: 'success', userId: result.insertId});
    });
}



  
app.get('/getUserData', (req, res) => {
    if(!req.session.userId) {
        return res.json({Status: 'Error', Error: 'User not logged in'});
    }

    const sql = "SELECT * FROM users WHERE id = ?";
    con.query(sql, [req.session.userId], (err, result) => {
        if (err) {
            return res.json({Status: 'Error', Error: 'Failed to fetch user data'});
        }

        if (result.length > 0) {
            return res.json({Status: 'Success', Data: result[0]});
        } else {
            return res.json({Status: 'Error', Error: 'User not found'});
        }
    });
});


app.get('/getAllAdmins',verifyToken, (req, res) => {
    const sql = "SELECT * FROM admins";
    con.query(sql, (err, result) => {
        if (err) {
            return res.json({Status: 'Error', Error: 'Failed to fetch admins data'});
        }

        if (result.length > 0) {
            return res.json({Status: 'Success', Data: result});
        } else {
            return res.json({Status: 'Error', Error: 'No admins found'});
        }
    });
});

app.get('/get-offer', (req, res) => {
    const sql = 'SELECT offer FROM offer WHERE id = ?';

    const accountId = 1;

    con.query(sql, [accountId], (err, result) => {
        if (err) {
            console.error('Error fetching offer:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the offer.' });
        }

        if (result.length > 0) {
            const offerValue = result[0].offer;
            res.status(200).json({ success: true, offer: offerValue });
        } else {
            res.status(404).json({ success: false, message: 'No offer found for the given account ID.' });
        }
    });
});


app.post('/changePassword', (req, res) => {
    const { username, oldPassword, newPassword } = req.body;
  
    const sql = "SELECT password FROM admins WHERE username = ?";
    
    con.query(sql, [username], (err, result) => {
      if (err || result.length === 0) {
        return res.json({ message: 'Username not found' });
      }
  
      const storedPassword = result[0].password;
  
      if (storedPassword !== oldPassword) { 
        return res.json({ message: 'Old password is incorrect' });
      }
  
      const updateSql = "UPDATE admins SET password = ? WHERE username = ?";
      
      con.query(updateSql, [newPassword, username], (updateErr, updateResult) => {
        if (updateErr) {
          return res.json({ message: 'Failed to update password' });
        }
  
        return res.json({ message: 'Password updated successfully' });
      });
    });
  });


app.post('/updateBalance', (req, res) => {
    const { productId, reward } = req.body;

    if (!req.session.userId) { 
        return res.json({ Status: 'Error', Error: 'User not logged in' });
    }

    const checkLastClickedSql = 'SELECT last_clicked FROM user_product_clicks WHERE user_id = ? AND product_id = ?';
    con.query(checkLastClickedSql, [req.session.userId, productId], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to check the last clicked time' });
        }

        const currentTime = new Date();

        if (result.length > 0) {
            const lastClicked = new Date(result[0].last_clicked);
            const timeDifference = currentTime - lastClicked;

            if (timeDifference < 12 * 60 * 60 * 1000) { 
                return res.json({ status: 'error', error: 'You have completed your task' });
            }
        }

        const updateBalanceSql = `UPDATE users SET balance = balance + ? WHERE id = ?`;
        con.query(updateBalanceSql, [reward,  req.session.userId], (err, updateResult) => {
            if (err) {
                console.log('Error updating balance:', err);
                
                return res.status(500).json({ status: 'error', error: 'Failed to update the balance and backend wallet' });
            }

            const updateLastClickedSql = `
                INSERT INTO user_product_clicks (user_id, product_id, last_clicked) 
                VALUES (?, ?, ?) 
                ON DUPLICATE KEY UPDATE last_clicked = VALUES(last_clicked)
            `;

            con.query(updateLastClickedSql, [req.session.userId, productId, currentTime], (err, clickResult) => {
                if (err) {
                    return res.status(500).json({ status: 'error', error: 'Failed to update the last clicked time' });
                }

                return res.json({ status: 'success', message: 'Balance and backend wallet updated successfully' });
            });
        });
    });
});




app.get('/getUserTaskStatus/:userId', (req, res) => {
    const userId = req.params.userId;
    const sql = 'SELECT * FROM user_product_clicks WHERE user_id = ?';
    
    con.query(sql, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch user task status' });
        }
        
        const taskStatus = results.reduce((acc, curr) => {
            acc[curr.product_id] = curr.last_clicked;
            return acc;
        }, {});

        res.json({ status: 'success', taskStatus });
    });
});
app.put('/updateProfile', async (req, res) => {
    if (!req.session.userId) {
      return res.status(401).json({ status: 'error', error: 'User not logged in' });
    }
  
    const { name } = req.body;
  
    if (!name) {
      return res.status(400).json({ status: 'error', error: 'Name is required' });
    }
  
    con.query('UPDATE users SET name = ? WHERE id = ?', [name, req.session.userId], (err, result) => {
      if (err) {
        return res.status(500).json({ status: 'error', error: 'Failed to update name' });
      }
  
      res.json({ status: 'success', message: 'Name updated successfully' });
    });
  });
  
  
  


app.post('/logout', (req, res) => {
    if (req.session) {
        req.session.destroy(err => {
            if (err) {
                return res.json({ Status: 'Error', Error: 'Failed to logout' });
            }

            return res.json({ Status: 'Success', Message: 'Logged out successfully' });
        });
    } else {
        return res.json({ Status: 'Error', Error: 'No session to logout' });
    }
});


    
    


app.post('/admin-login', (req, res) => {
    const sentloginUserName = req.body.LoginUserName;
    const sentLoginPassword = req.body.LoginPassword;

    const sql = 'SELECT * FROM admins WHERE username = ? && password = ?';
    const values = [sentloginUserName, sentLoginPassword];

    con.query(sql, values, (err, results) => {
        if (err) {
            res.status(500).send({ error: err });
        }
        if (results.length > 0) {
            const token = jwt.sign({ username: sentloginUserName ,isAdmin: true}, 'your_secret_key', { expiresIn: '30d' });
            res.status(200).send({ token });
        } else {
            res.status(401).send({ message: `Credentials don't match!` });
        }
    });
});



app.get('/approved-users', (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.perPage) || 10;
    const searchTerm = req.query.searchTerm || ''; 
    const sortKey = req.query.sortKey || 'id';
    const sortDirection = req.query.sortDirection || 'asc'; 


    let sql = `SELECT id,balance,team,name,email,phoneNumber,backend_wallet,trx_id,total_withdrawal,CurrTeam,refer_by,password,today_wallet FROM  users
    WHERE 
        approved = 1
        AND payment_ok = 1`;

    if (searchTerm) {
        sql += ` AND (name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%' OR id = '${searchTerm}')`;
    } else {
        sql += ` AND (CurrTeam >= 3 OR team >= 5) `;
    }


    const countSql = `SELECT COUNT(*) AS totalCount FROM users WHERE approved = 1 AND payment_ok = 1 ${searchTerm ? `AND (name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%' OR id = '${searchTerm}')` : ''}`;


    con.query(countSql, (countErr, countResult) => {
        if (countErr) {
            console.error('Count Query Error:', countErr); 
            return res.status(500).json({ success: false, message: 'An error occurred while fetching total count.' });
        }

        const totalCount = countResult[0].totalCount;

        sql += ` ORDER BY ${sortKey} ${sortDirection}`;

        con.query(sql, (err, result) => {
            if (err) {
                console.error('Main Query Error:', err); 
                return res.status(500).json({ success: false, message: 'An error occurred while fetching approved users.' });
            }

            res.status(200).json({
                success: true,
                approvedUsers: result,
                
                totalCount: totalCount,
                currentPage: page,
                totalPages: Math.ceil(totalCount / perPage)
            });
        });
    });


        
});
   
app.get('/approved-users-spec',verifyToken, (req, res) => {
    const page = parseInt(req.query.page) || 1;
 


    let sql = `SELECT id,balance,team,name,email,today_wallet,phoneNumber,backend_wallet,trx_id,total_withdrawal,CurrTeam,refer_by,password FROM  users
    WHERE 
        approved = 1
        AND payment_ok = 1 AND id between 5201 and 5205`;





        con.query(sql, (err, result) => {
            if (err) {
                console.error('Main Query Error:', err); 
                return res.status(500).json({ success: false, message: 'An error occurred while fetching approved users.' });
            }

            res.status(200).json({
                success: true,
                approvedUsers: result,
                
                currentPage: page,
            });
        });
    });


        



        
  

function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 


    if (!token) {
        return res.status(403).json({ success: false, message: `No token provided ${token}` });
    }

    jwt.verify(token, 'your_secret_key', (err, decoded) => {
        if (err) {
            return res.status(401).json({ success: false, message: 'Failed to authenticate token.' });
        }

        if (!decoded.isAdmin) {
            return res.status(403).json({ success: false, message: 'Not authorized to access this resource.' });
        }

        next();
    });
}

app.get('/users-by-email', verifyToken,(req, res) => {



    const email = req.query.email || ''; 
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.perPage) || 10;
    const sortKey = req.query.sortKey || 'id';
    const sortDirection = req.query.sortDirection || 'asc';

    let sql = `SELECT id,balance,team,backend_wallet, name,email,phoneNumber,trx_id,total_withdrawal,CurrTeam,refer_by,password,today_wallet FROM  users
    WHERE 
        approved = 1
        AND payment_ok = 1`;
    if (email) {
        sql += ` AND (email LIKE '%${email}%' OR id = '${email}' OR trx_id LIKE '%${email}%')`;
    } else {
        sql += ` AND (CurrTeam >= 3 OR team >= 5)`;
    }


    const countSql = `SELECT COUNT(*) AS totalCount FROM users WHERE approved = 1 AND payment_ok = 1 ${email ? `AND email LIKE '%${email}%'` : ''}`;


    con.query(countSql, (countErr, countResult) => {
        if (countErr) {
            console.error('Count Query Error:', countErr); 
            return res.status(500).json({ success: false, message: 'An error occurred while fetching total count.' });
        }

        const totalCount = countResult[0].totalCount;

        sql += ` ORDER BY ${sortKey} ${sortDirection}`;

        con.query(sql, (err, result) => {
            if (err) {
                console.error('Main Query Error:', err);
                return res.status(500).json({ success: false, message: 'An error occurred while fetching users by email.' });
            }

            res.status(200).json({
                success: true,
                users: result,
                totalCount: totalCount,
                currentPage: page,
                totalPages: Math.ceil(totalCount / perPage)
            });
        });
    });
});

app.get('/todayApproved', (req, res) => {
   

    const sql = `SELECT * FROM users WHERE approved = 1 AND approved_at >= CURDATE() AND payment_ok = 1`;

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', approvedUsers: result });
        } else {
            return res.status(404).json({ status: 'error', error: 'No approved users found' });
        }
    });
});


app.put('/rejectUser/:userId', (req, res) => {
    const userId = req.params.userId;

    if (!userId) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }

    const sql = `
        UPDATE users 
        SET 
            rejected = 1, 
            payment_ok = 0,
            trx_id =null,
            approved = 0,
       
                        rejected_at = CURRENT_TIMESTAMP 
        WHERE id = ? AND rejected = 0`;

    con.query(sql, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to reject user' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found or already rejected' });
        }

        res.json({ status: 'success', message: 'User rejected successfully' });
    });
});


app.get('/rejectedUsers', (req, res) => {
    const sql = 'SELECT * FROM users WHERE rejected = 1 ';

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', approvedUsers: result });
        } else {

        }
    });
});


app.get('/EasypaisaUsers', (req, res) => {
    const { type } = req.query; // Use req.query to get query parameters
console.log(type);
    // SQL query to select users based on type
    const sql = 'SELECT id,trx_id,refer_by,name,email,sender_name,sender_number FROM users WHERE approved = 0 AND payment_ok = 1 AND type = ?';

    con.query(sql, [type], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', approvedUsers: result });
        } else {
            return res.status(404).json({ status: 'error', error: 'No approved users found' });
        }
    });
});



app.post('/withdraw', (req, res) => {
     
    if (!req.session.userId) {
        return res.status(401).json({ status: 'error', error: 'User not logged in' });
    }

    const userId = req.session.userId;
    const { amount, accountName, accountNumber, bankName, CurrTeam, totalWithdrawn, team, coin_address } = req.body;

    if (!amount || !userId) {
        return res.status(400).json({ status: 'error', error: 'All fields are required' });
    }

    const checkRequestSql = `
        SELECT * FROM withdrawal_requests
        WHERE user_id = ? AND approved = 'pending' AND reject = 0
    `;

    con.query(checkRequestSql, [userId], (err, results) => {
        if (err) {
            console.log(err);
            return res.status(500).json({ status: 'error', error: 'Failed to check for existing requests', details: err.message });
        }

        if (results.length > 0) {
            return res.status(400).json({ status: 'error', error: 'You already have a pending withdrawal request' });
        }

        const getUserSql = `
            SELECT level, balance,team FROM users WHERE id = ?
        `;

        con.query(getUserSql, [userId], (err, userResults) => {
            if (err) {
                return res.status(500).json({ status: 'error', error: 'Failed to fetch user details', details: err.message });
            }

            if (userResults.length === 0) {
                return res.status(500).json({ status: 'error', error: 'User not found' });
            }

            const userLevel = userResults[0].level;
            const userBalance = userResults[0].balance;
            const userTeam = userResults[0].team;
            if (userTeam <= 0) {
                console.log('User has no team');
                
                return res.status(400).json({ status: 'error', error: 'You Cannot withdraw this amount' });
            }

            const checkLimitsSql = `
                SELECT * FROM withdraw_limit
                WHERE level = ? AND ? >= min AND ? <= max
            `;

            con.query(checkLimitsSql, [userLevel, amount, amount], (err, limitResults) => {
                if (err) {
                    return res.status(500).json({ status: 'error', error: 'Failed to check withdrawal limits', details: err.message });
                }

                if (limitResults.length === 0) {
                    return res.status(400).json({ status: 'error', error: 'You Cannot withdraw this amount' });
                }

                const getExchangeFeeSql = `
                    SELECT fee FROM exchange_fee WHERE id = 1
                `;

                con.query(getExchangeFeeSql, (err, feeResults) => {
                    if (err) {
                        return res.status(500).json({ status: 'error', error: 'Failed to fetch exchange fee', details: err.message });
                    }

                    if (feeResults.length === 0) {
                        return res.status(500).json({ status: 'error', error: 'Exchange fee not found' });
                    }

                    const feePercentage = feeResults[0].fee;
                    const fee = (amount * feePercentage) / 100;
                    const amountAfterFee = amount - fee;

                    if (amountAfterFee <= 0) {
                        return res.status(400).json({ status: 'error', error: 'Amount after fee must be greater than zero' });
                    }

                    if (userBalance < amount) {
                        return res.status(400).json({ status: 'error', error: 'Insufficient balance' });
                    }

                    con.beginTransaction(err => {
                        if (err) {
                            return res.status(500).json({ status: 'error', error: 'Failed to start transaction' });
                        }

                        const withdrawSql = `
                            INSERT INTO withdrawal_requests (user_id, amount, account_name, account_number, bank_name, CurrTeam, total_withdrawn, team, request_date, approved, approved_time, coin_address, fee)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), 'pending', NOW(), ?, ?)
                        `;

                        con.query(withdrawSql, [userId, amountAfterFee, accountName, accountNumber, bankName, CurrTeam, totalWithdrawn, team, coin_address, fee], (err, withdrawResult) => {
                            if (err) {
                                return con.rollback(() => {
                                    console.log(err);
                                    res.status(500).json({ status: 'error', error: 'Failed to make withdrawal', details: err.message });
                                });
                            }

                            con.commit(err => {
                                if (err) {
                                    return con.rollback(() => {
                                        res.status(500).json({ status: 'error', error: 'Failed to commit transaction', details: err.message });
                                    });
                                }
                                res.json({ status: 'success', message: 'Withdrawal request submitted successfully' });
                            });
                        });
                    });
                });
            });
        });
    });
});



app.get('/fetchCommissionData', (req, res) => {
    const sql = 'SELECT * FROM commission';

    con.query(sql, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch commission data' });
        }

        res.json({ status: 'success', data: result });
    });
});

app.get('/fetchLevelsData', (req, res) => {
    const sql = 'SELECT * FROM levels';

    con.query(sql, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch commission data' });
        }

        res.json({ status: 'success', data: result });
    });
});
app.get('/fetchLimitsData', (req, res) => {
    const sql = 'SELECT * FROM withdraw_limit';

    con.query(sql, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch commission data' });
        }

        res.json({ status: 'success', data: result });
    });
});

app.put('/updateLevelData', (req, res) => {
    const { id, min_team, max_team, level } = req.body;

    if (!min_team || !max_team || !level) {
        return res.status(400).json({ status: 'error', message: 'Min Team, Max Team, and Level are required' });
    }

    let updateQuery = `
        UPDATE levels
        SET 
            min_team = ?,
            max_team = ?,
            level = ?
        WHERE id = ?`;
    let queryParams = [min_team, max_team, level, id];


    con.query(updateQuery, queryParams, (err, result) => {
        if (err) {
            console.error('Error updating level data:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update level data' });
        }


        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'Level data not found' });
        }

        res.json({ status: 'success', message: 'Level data updated successfully' });
    });
});
app.put('/updateWithdrawData', (req, res) => {
    const { id, min,  level } = req.body;

    if (!min || !level) {
        return res.status(400).json({ status: 'error', message: 'Min Team,  and Level are required' });
    }

    let updateQuery = `
        UPDATE withdraw_limit

        SET 
            min = ?,
            level = ?
        WHERE id = ?`;
    let queryParams = [min,  level, id];


    con.query(updateQuery, queryParams, (err, result) => {
        if (err) {
            console.error('Error updating level data:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update level data' });
        }


        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'Level data not found' });
        }

        res.json({ status: 'success', message: 'Level data updated successfully' });
    });
});
app.put('/updateCommissionData', (req, res) => {
    const { id, direct_bonus, indirect_bonus } = req.body;

    if (!direct_bonus || !indirect_bonus) {
        return res.status(400).json({ status: 'error', message: 'Direct Bonus and Indirect Bonus are required' });
    }

    let updateQuery;
    let queryParams;

    if (id === 0) {
        updateQuery = `
            UPDATE commission
            SET 
                direct_bonus = ?,
                indirect_bonus = ?
            WHERE id = 0`;
        queryParams = [direct_bonus, indirect_bonus];
    } else {
        updateQuery = `
            UPDATE commission
            SET 
                direct_bonus = ?,
                indirect_bonus = ?
            WHERE id = ?`;
        queryParams = [direct_bonus, indirect_bonus, id];
    }


    con.query(updateQuery, queryParams, (err, result) => {
        if (err) {
            console.error('Error updating commission data:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update commission data' });
        }


        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'Commission data not found' });
        }

        res.json({ status: 'success', message: 'Commission data updated successfully' });
    });
});




app.put('/updateUserAccount/:userId', (req, res) => {
    const user_id = req.params.userId;
    const { accountNumber, nameOnAccount, bankName } = req.body;

    if (!user_id || !accountNumber || !nameOnAccount || !bankName) {
        return res.status(400).json({ status: 'error', message: 'User ID, Account Number, Name on Account, and Bank Name are required' });
    }

    let updateQuery = `
        UPDATE users_accounts
        SET 
            holder_name = ?,
            holder_number = ?,
            bankName = ?
        WHERE user_id = ?`;
    let updateParams = [nameOnAccount, accountNumber, bankName, user_id];

    con.query(updateQuery, updateParams, (err, updateResult) => {
        if (err) {
            console.error('Error updating user account:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update user account' });
        }

        if (updateResult.affectedRows === 0) {
            let insertQuery = `
                INSERT INTO users_accounts (user_id, holder_name, holder_number, bankName)
                VALUES (?, ?, ?, ?)`;
            let insertParams = [user_id, nameOnAccount, accountNumber, bankName];

            con.query(insertQuery, insertParams, (err, insertResult) => {
                if (err) {
                    console.error('Error inserting user account:', err);
                    return res.status(500).json({ status: 'error', error: 'Failed to insert user account' });
                }

                res.json({ status: 'success', message: 'User account inserted successfully' });
            });
        } else {
            res.json({ status: 'success', message: 'User account updated successfully' });
        }
    });
});



app.put('/updateUser', (req, res) => {
    if (!req.body.id) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }

    const { id, name, email, balance,backend_wallet,CurrTeam, trx_id, total_withdrawal,today_wallet } = req.body;

    const sql = `
        UPDATE users 
        SET 
            name = ?, 
            email = ?, 
            balance = ?, 
            backend_wallet = ? ,
            CurrTeam = ?,
            trx_id = ?, 
            total_withdrawal = ?  ,
            today_wallet = ?
        WHERE id = ?`;

    con.query(sql, [name, email, balance,backend_wallet,CurrTeam, trx_id, total_withdrawal,today_wallet, id], (err, result) => {
        if (err) {
            console.error(err); 
            return res.status(500).json({ status: 'error', error: 'Failed to update user' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        res.json({ status: 'success', message: 'User updated successfully' });
    });
});

function queryAsync(query, params) {
    return new Promise((resolve, reject) => {
        con.query(query, params, (error, results, fields) => {
            if (error) {
                return reject(error);
            }
            resolve(results);
        });
    });
}
const updateTeamAndDate = async (userId) => {
    try {
        const userResult = await queryAsync(`
            SELECT last_week_team_update, week_team
            FROM users
            WHERE id = ?
        `, [userId]);

        const { last_week_team_update, week_team } = userResult[0];
        const currentDate = new Date();

        if (!last_week_team_update) {
            await queryAsync(`
                UPDATE users
                SET last_week_team_update = CURRENT_DATE,
                    week_team = week_team + 1
                WHERE id = ?
            `, [userId]);
        } else {
            const lastUpdateDate = new Date(last_week_team_update);
            const daysDifference = Math.floor((currentDate - lastUpdateDate) / (1000 * 60 * 60 * 24));

            if (daysDifference > 7) {
                await queryAsync(`
                    UPDATE users
                    SET last_week_team_update = CURRENT_DATE,
                        week_team = 1
                    WHERE id = ?
                `, [userId]);
            } else {
                await queryAsync(`
                    UPDATE users
                    SET week_team = week_team + 1
                    WHERE id = ?
                `, [userId]);
            }
        }
    } catch (error) {
        console.error('Error updating team and date:', error);
        throw error;
    }
};



// Define your route handler
app.put('/approveUser/:userId', async (req, res) => {
    const userId = req.params.userId;

    if (!userId) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }

    const updateReferredUserQuery = `
    UPDATE users 
    SET 
        approved = 1, 
        payment_ok = 1,
        rejected = 0,
        approved_at = CURRENT_TIMESTAMP,
        backend_wallet = backend_wallet + (
            SELECT joining_fee * (SELECT initial_percent FROM initial_fee WHERE id = 1) / 100
            FROM joining_fee
            WHERE id = 1
        ) 
    WHERE id = ?`;

    const getReferrerIdQuery = `
        SELECT refer_by
        FROM users
        WHERE id = ?`;

    const getJoiningFeeQuery = `
        SELECT joining_fee
        FROM joining_fee
        WHERE id = 1`;

    const incrementTeamAndLevelForReferrerQuery = `
        UPDATE users AS u1
        JOIN levels AS l ON u1.team + 1 >= l.min_team AND u1.team + 1 <= l.max_team
        SET u1.team = u1.team + 1,
            u1.level = l.level,
            u1.balance = IF(u1.level <> l.level, u1.balance + 40, u1.balance)
        WHERE u1.id = ?;`;

    const incrementWeakTeamofReferrerQuery = `
        UPDATE users
        SET weak_team = weak_team + 1
        WHERE id = ?;`;

   
        const updateBalancesAndWallet = async (userId, depth) => {
            if (depth >= 7) return; // Limit to 7 levels of referrers
        
            try {
                const referrerResult = await queryAsync(getReferrerIdQuery, [userId]);
                const referrerId = referrerResult[0]?.refer_by;
        
                if (referrerId) {
                    // Fetch both direct and indirect bonuses based on depth
                    const commissionResult = await queryAsync(`
                        SELECT direct_bonus, indirect_bonus ,extra_balance
                        FROM commission
                        WHERE id = ?
                    `, [depth]);
        
                    const directBonus = commissionResult[0]?.direct_bonus || 0;
                    const indirectBonus = commissionResult[0]?.indirect_bonus || 0;
                    const extraBalance = commissionResult[0]?.extra_balance || 0;
        
                    // Fetch the joining fee
                    const feeResult = await queryAsync(getJoiningFeeQuery);
                    const joiningFee = feeResult[0]?.joining_fee || 0;
        
                    // Calculate the percentage of bonuses based on the joining fee
                    const directBonusAmount = (directBonus * (joiningFee / 100));
                    const indirectBonusAmount = (indirectBonus * (joiningFee / 100));

                    const extraBalanceAmount = (extraBalance * (joiningFee / 100));
        
                    // Update referrer's balance with direct bonus and backend_wallet with indirect bonus
                    await queryAsync(`
                        UPDATE users
                        SET 
                            balance = balance + ?,
                            backend_wallet = backend_wallet + ?,
                            extra_balance = extra_balance + ?
                        WHERE id = ?
                    `, [directBonusAmount, indirectBonusAmount, extraBalanceAmount, referrerId]);
        
                    // Recursively update the chain for the next referrer
                    await updateBalancesAndWallet(referrerId, depth + 1);
                } else {
                    console.log('Reached top of referral hierarchy');
                }
            } catch (error) {
                console.error('Error updating balances and wallet:', error);
                throw error;
            }
        };
        

    try {
        await queryAsync('START TRANSACTION');

        await queryAsync(updateReferredUserQuery, [userId]);

        await updateBalancesAndWallet(userId, 0);

        const referrerResult = await queryAsync(getReferrerIdQuery, [userId]);
        const referrerId = referrerResult[0]?.refer_by;

        if (referrerId) {
            await queryAsync(incrementTeamAndLevelForReferrerQuery, [referrerId]);
            await queryAsync(incrementWeakTeamofReferrerQuery, [referrerId]);
        } else {
            console.log('Reached top of referral hierarchy');
        }

        await updateTeamAndDate(referrerId); // Call this function to update team and date

        await queryAsync('COMMIT');
        res.status(200).json({ status: 'success', message: 'User approved and referrer chain updated' });
    } catch (error) {
        console.error('Transaction error:', error);
        await queryAsync('ROLLBACK');
        res.status(500).json({ status: 'error', error: 'Transaction failed' });
    }
});


app.post('/sellExtraBalance', (req, res) => {
    const { amount } = req.body;
    const userId = req.session.userId;
console.log(amount, userId);

    if (!userId || !amount || amount <= 0) {
        return res.status(400).json({ success: false, message: 'Invalid input data.' });
    }

    const checkBalanceSql = 'SELECT extra_balance FROM users WHERE id = ?';
    con.query(checkBalanceSql, [userId], (err, results) => {
        if (err) {
            console.error('Error checking balance:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while checking the balance.' });
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        const currentExtraBalance = results[0].extra_balance;
        console.log('Current Extra Balance:', currentExtraBalance); // Log current balance

        if (currentExtraBalance < amount) {
            return res.status(400).json({ success: false, message: 'Insufficient extra balance.' });
        }

        const updateBalanceSql = `
            UPDATE users 
            SET extra_balance = extra_balance - ?, balance = balance + ?
            WHERE id = ?
        `;
        con.query(updateBalanceSql, [amount, amount, userId], (err, result) => {
            if (err) {
                console.error('Error updating balance:', err);
                return res.status(500).json({ success: false, message: 'An error occurred while updating the balance.' });
            }

            if (result.affectedRows > 0) {
                console.log('Balance updated successfully'); // Log successful update
                res.status(200).json({ success: true, message: 'Extra balance sold successfully.' });
            } else {
                console.error('Failed to update the balance. Affected Rows:', result.affectedRows);
                res.status(500).json({ success: false, message: 'Failed to update the balance.' });
            }
        });
    });
});




app.get('/fetchClickedButtonsweek', (req, res) => {
    const  userId  = req.session.userId;
  
    if (!userId) {
      return res.status(400).json({ status: 'error', message: 'userId is required' });
    }
  
    const sql = `
      SELECT buttonId
      FROM week_button_clicks
      WHERE userId = ?
    `;
  
    con.query(sql, [userId], (err, results) => {
      if (err) {
        console.error('Error fetching clicked buttons:', err);
        return res.status(500).json({ status: 'error', message: 'Failed to fetch clicked buttons', error: err });
      }
  
      const clickedButtons = {};
      results.forEach(row => {
        clickedButtons[row.buttonId] = true;
      });
  
      res.json({ status: 'success', clickedButtons });
    });
  });

  
app.post('/collectBonus', (req, res) => {
    const userId = req.session.userId;
    if (!userId) {
        console.log('Unauthorized access attempt');
        return res.status(401).json({ status: 'error', message: 'Unauthorized' });
    }

    const getUserQuery = `SELECT level_updated, balance, level FROM users WHERE id = ?`;
    con.query(getUserQuery, [userId], (err, result) => {
        if (err) {
            console.error('Database error while retrieving user data:', err);
            return res.status(500).json({ status: 'error', message: 'Failed to retrieve user data' });
        }

        if (result.length === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        const user = result[0];

        if (user.level_updated === 1) {
            const getBonusAmountQuery = `SELECT increment_amount FROM level_bonus WHERE level = ?`;

            con.query(getBonusAmountQuery, [user.level], (err, bonusResult) => {
                if (err) {
                    console.error('Database error while retrieving bonus amount:', err);
                    return res.status(500).json({ status: 'error', message: 'Failed to retrieve bonus amount' });
                }

                if (bonusResult.length === 0) {
                    return res.status(404).json({ status: 'error', message: 'No bonus amount found for this level' });
                }

                const bonusAmount = bonusResult[0].increment_amount;

                const updateBalanceQuery = `UPDATE users SET balance = balance + ?, level_updated = 0 WHERE id = ?`;
                con.query(updateBalanceQuery, [bonusAmount, userId], (err) => {
                    if (err) {
                        console.error('Database error while updating balance:', err);
                        return res.status(500).json({ status: 'error', message: 'Failed to update balance' });
                    }

                    const logBonusQuery = `INSERT INTO bonus_history_level_up (user_id, bonus_amount) VALUES (?, ?)`;
                    con.query(logBonusQuery, [userId, bonusAmount], (err) => {
                        if (err) {
                            console.error('Database error while logging bonus collection:', err);
                            return res.status(500).json({ status: 'error', message: 'Failed to log bonus collection' });
                        }

                        res.json({ status: 'success', message: 'Bonus collected and logged successfully!' });
                    });
                });
            });
        } else if (user.level_updated === 0) {
            console.log('Bonus already collected for user ID:', userId);
            return res.status(403).json({ status: 'error', message: 'You have already collected your bonus' });
        } else {
            console.log('User is not eligible to collect the bonus for user ID:', userId);
            return res.status(403).json({ status: 'error', message: 'You are not eligible to collect the bonus' });
        }
    });
});

app.get('/getBonusDetails', (req, res) => {
    const query = `
        SELECT 
            l.level, 
            lb.increment_amount AS bonus, 
            l.min_team, 
            l.max_team
        FROM 
            levels AS l
        LEFT JOIN 
            level_bonus AS lb 
        ON 
            l.level = lb.level
        ORDER BY 
            l.level
    `;

    con.query(query, (err, results) => {
        if (err) {
            console.error('Database error while retrieving level data:', err);
            return res.status(500).json({ status: 'error', message: 'Failed to retrieve level data' });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: 'error', message: 'No level data found' });
        }

        // Map results to a more readable format
        const levelsData = results.map(row => ({
            level: row.level,
            bonus: row.bonus,
            minTeam: row.min_team,
            maxTeam: row.max_team
        }));

        res.json({ status: 'success', levels: levelsData });
    });
});


app.post('/weeklytrackButton', (req, res) => {
const { userId, buttonId } = req.body;
console.log(req.body);
 
if (!userId || !buttonId) {
      return res.status(400).json({ status: 'error', message: 'userId and buttonId are required' });
    }
      const checkUserLevelSql = `
      SELECT level FROM users WHERE id = ?;
    `;
  
    con.query(checkUserLevelSql, [userId], (err, results) => {
      if (err) {
        console.error('Error fetching user level:', err);
        return res.status(500).json({ status: 'error', message: 'Failed to check user level', error: err });
      }
  
      if (results.length === 0) {
        return res.status(404).json({ status: 'error', message: 'User not found' });
      }
  
      const userLevel = results[0].level;
  
      if (userLevel < 2) {
        return res.status(403).json({ status: 'error', message: 'You can withdraw salary on level 2 or above' });
      }
  
      // Continue with original logic if user level is 2 or above
      const clickTime = new Date().toISOString().slice(0, 19).replace('T', ' ');
  
      let bonusValue;
      switch (buttonId) {
        case 1:
          bonusValue = 10.00;
          break;
        case 2:
          bonusValue = 25.00;
          break;  
        default:
          return res.status(400).json({ status: 'error', message: 'Invalid buttonId' });
      }
  
      const insertButtonClickSql = `
        INSERT INTO week_button_clicks (userId, buttonId, clickTime)
        VALUES (?, ?, ?);
      `;
  
      con.query(insertButtonClickSql, [userId, buttonId, clickTime], (err, result) => {
        if (err) {
          console.error('Error tracking button click:', err);
          return res.status(500).json({ status: 'error', message: 'Failed to track button click', error: err });
        }
  
        const insertHistorySql = `
          INSERT INTO week_bonus_history (user_id, amount, buttonId, created_at)
          VALUES (?, ?, ?, ?);
        `;
  
        con.query(insertHistorySql, [userId, bonusValue, buttonId, clickTime], (err, result) => {
          if (err) {
            console.error('Error inserting into history:', err);
            return res.status(500).json({ status: 'error', message: 'Failed to insert into history', error: err });
          }
  
          res.json({ status: 'success', message: 'Button click tracked and history updated successfully' });
        });
      });
    });
  });
  

app.get('/fetchClickedButtons', (req, res) => {
    const  userId  = req.session.userId;
  
    if (!userId) {
      return res.status(400).json({ status: 'error', message: 'userId is required' });
    }
  
    const sql = `
      SELECT buttonId
      FROM user_button_clicks
      WHERE userId = ?
    `;
  
    con.query(sql, [userId], (err, results) => {
      if (err) {
        console.error('Error fetching clicked buttons:', err);
        return res.status(500).json({ status: 'error', message: 'Failed to fetch clicked buttons', error: err });
      }
  
      const clickedButtons = {};
      results.forEach(row => {
        clickedButtons[row.buttonId] = true;
      });
  
      res.json({ status: 'success', clickedButtons });
    });
  });
  app.post('/trackButton', (req, res) => {
    const { userId, buttonId } = req.body;
  
    if (!userId || !buttonId) {
      console.error(`[ERROR] Missing userId or buttonId: userId=${userId}, buttonId=${buttonId}`);
      return res.status(400).json({ status: 'error', message: 'userId and buttonId are required' });
    }
  
    const clickTime = new Date().toISOString().slice(0, 19).replace('T', ' ');
    const bonusLevels = [
        { members: 5, bonus: 1.5 },
        { members: 15, bonus: 4 },
        { members: 35, bonus: 5 },
        { members: 65, bonus: 7.5 },
        { members: 105, bonus: 10 },
        { members: 155, bonus: 15 },
      ];
    
    // Map buttonId to respective bonus values
    const bonusMapping = {
      5: 1.5,
      15: 4,
      35: 5,
      65: 7.5,
      105: 10,
      155: 15
    };
  
    const bonusValue = bonusMapping[buttonId];
    if (!bonusValue) {
      console.error(`[ERROR] Invalid buttonId received: ${buttonId}`);
      return res.status(400).json({ status: 'error', message: 'Invalid buttonId' });
    }
  
    console.log(`[INFO] Tracking button click: userId=${userId}, buttonId=${buttonId}, bonusValue=${bonusValue}`);
  
    // Update user balance
    const updateBalanceSql = `
      UPDATE users
      SET balance = balance + ?
      WHERE id = ?;
    `;
  
    con.query(updateBalanceSql, [bonusValue, userId], (err, result) => {
      if (err) {
        console.error(`[ERROR] Failed to update balance for userId=${userId}:`, err);
        return res.status(500).json({ status: 'error', message: 'Failed to update balance', error: err });
      }
  
      console.log(`[INFO] Balance updated successfully for userId=${userId}, bonusValue=${bonusValue}`);
  
      // Insert button click record
      const insertButtonClickSql = `
        INSERT INTO user_button_clicks (userId, buttonId, clickTime)
        VALUES (?, ?, ?);
      `;
  
      con.query(insertButtonClickSql, [userId, buttonId, clickTime], (err, result) => {
        if (err) {
          console.error(`[ERROR] Failed to track button click for userId=${userId}, buttonId=${buttonId}:`, err);
          return res.status(500).json({ status: 'error', message: 'Failed to track button click', error: err });
        }
  
        console.log(`[INFO] Button click tracked successfully for userId=${userId}, buttonId=${buttonId}`);
  
        // Insert into bonus history
        const insertHistorySql = `
          INSERT INTO bonus_history (user_id, amount, created_at)
          VALUES (?, ?, ?);
        `;
  
        con.query(insertHistorySql, [userId, bonusValue, clickTime], (err, result) => {
          if (err) {
            console.error(`[ERROR] Failed to insert bonus history for userId=${userId}, amount=${bonusValue}:`, err);
            return res.status(500).json({ status: 'error', message: 'Failed to insert into history', error: err });
          }
  
          console.log(`[INFO] Bonus history inserted successfully for userId=${userId}, amount=${bonusValue}`);
          res.json({ status: 'success', message: 'Button click tracked and history updated successfully' });
        });
      });
    });
  });
  
  
app.post('/update-password', (req, res) => {
    const userId = req.session.userId;
    const { currentPassword, newPassword } = req.body;

    if (!userId) {
        return res.status(401).json({ success: false, message: 'User not logged in' });
    }

    const getPasswordSql = 'SELECT password FROM users WHERE id = ?';

    con.query(getPasswordSql, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const currentStoredPassword = results[0].password;

        if (currentPassword !== currentStoredPassword) {
            return res.status(400).json({ success: false, message: 'Current password is incorrect' });
        }

        const updatePasswordSql = 'UPDATE users SET password = ? WHERE id = ?';
        
        con.query(updatePasswordSql, [newPassword, userId], (err) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Failed to update password' });
            }

            res.json({ success: true, message: 'Password updated successfully' });
        });
    });
});



app.get('/withdrawal-requests', (req, res) => {
    const userId = req.session.userId;

    if (!userId) {
        return res.status(401).json({ error: 'User not logged in' });
    }

    const sql = 'SELECT user_id, request_date, reject, amount, bank_name, approved FROM withdrawal_requests WHERE user_id = ? ORDER BY request_date DESC';

    con.query(sql, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch withdrawal requests' });
        }

        const formattedResults = results.map(request => ({
            id: request.user_id,
            date: request.request_date,
            amount: request.amount,
            bank_name: request.bank_name,
            approved: request.approved,
            reject: request.reject
        }));
        res.json(formattedResults);
    });
});
app.get('/user-salary-requests', (req, res) => {
    const userId = req.session.userId;

    if (!userId) {
        return res.status(401).json({ error: 'User not logged in' });
    }

    const sql = 'SELECT user_id, created_at,  amount, approved FROM week_bonus_history WHERE user_id = ? ORDER BY created_at DESC';

    con.query(sql, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch withdrawal requests' });
        }

        const formattedResults = results.map(request => ({
            id: request.user_id,
            date: request.created_at,
            amount: request.amount,
            approved: request.approved,
        }));
        res.json(formattedResults);
    });
});



  app.get('/all-withdrawal-requests', (req, res) => {
    const sql = 'SELECT * FROM withdrawal_requests WHERE approved = "pending" && reject = "0"';
    con.query(sql, (error, results) => {
        if (error) {
            res.status(500).json({ error: 'Internal Server Error' });
            return;
        }
        const mappedResults = results.map(item => ({
            id: item.id,
            user_id: item.user_id,
            amount: item.amount,
            account_name: item.account_name,
            bank_name: item.bank_name,
            CurrTeam: item.CurrTeam,
            account_number: item.account_number,
            approved: item.approved === 1 ,
            team: item.team,
            total_withdrawn: item.total_withdrawn
        }));
        res.json(mappedResults);
    });
});
app.get('/all-salary-requests', (req, res) => {
    const sql = `
        SELECT wbh.id, wbh.user_id, wbh.amount, u.team, u.name
        FROM week_bonus_history wbh
        JOIN users u ON wbh.user_id = u.id
        WHERE wbh.approved = 0
    `;

    con.query(sql, (error, results) => {
        if (error) {
            res.status(500).json({ error: 'Internal Server Error' });
            return;
        }

        const mappedResults = results.map(item => ({
            id: item.id,
            user_id: item.user_id,
            amount: item.amount,
            team: item.team,
            name: item.name,
        }));

        res.json(mappedResults);
    });
});

// Approve salary request
app.post('/approve-salary-request', (req, res) => {
    const { userId, requestId, amount } = req.body;
    console.log(userId, requestId, amount);

    if (!userId || !requestId || !amount) {
        return res.status(400).json({ error: 'User ID, request ID, and amount are required' });
    }

    // Begin transaction
    con.beginTransaction(err => {
        if (err) {
            console.error('Error starting transaction:', err);
            return res.status(500).json({ error: 'Failed to start transaction' });
        }

        // Query to get the buttonId for the given requestId
        const getButtonIdSql = 'SELECT buttonId FROM week_bonus_history WHERE id = ?';
        con.query(getButtonIdSql, [requestId], (err, results) => {
            if (err) {
                return con.rollback(() => {
                    console.error('Error fetching buttonId:', err);
                    res.status(500).json({ error: 'Failed to fetch buttonId' });
                });
            }

            if (results.length === 0) {
                return con.rollback(() => {
                    res.status(404).json({ error: 'Request not found' });
                });
            }

            const buttonId = results[0].buttonId;
            console.log(`buttonId: ${buttonId} userId: ${userId}`);

            // Update user balance
            const updateBalanceSql = `
                UPDATE users
                SET balance = balance + ?, total_salary = total_salary + ?
                WHERE id = ?
            `;
            con.query(updateBalanceSql, [amount, amount, userId], (err) => {
                if (err) {
                    return con.rollback(() => {
                        console.error('Error updating user balance:', err);
                        res.status(500).json({ error: 'Failed to update user balance' });
                    });
                }

                // Update week_bonus_history
                const updateWeekBonusHistorySql = `
                    UPDATE week_bonus_history
                    SET approved = 1
                    WHERE id = ?
                `;
                con.query(updateWeekBonusHistorySql, [requestId], (err) => {
                    if (err) {
                        return con.rollback(() => {
                            console.error('Error updating week_bonus_history:', err);
                            res.status(500).json({ error: 'Failed to update week_bonus_history' });
                        });
                    }

                    // Update week_team based on buttonId
                    let updateWeekTeamSql;
                    let updateWeekTeamValues;

                    if (buttonId === 1) {
                        updateWeekTeamSql = 'UPDATE users SET week_team = week_team - 25 WHERE id = ?';
                        updateWeekTeamValues = [userId];
                    } else if (buttonId === 2) {
                        updateWeekTeamSql = 'UPDATE users SET week_team = 0 WHERE id = ?';
                        updateWeekTeamValues = [userId];
                    } else {
                        updateWeekTeamSql = null;
                        updateWeekTeamValues = null;
                    }

                    // Delete the button click record
                    const deleteButtonClickSql = 'DELETE FROM week_button_clicks WHERE userId = ? AND buttonId = ?';
                    con.query(deleteButtonClickSql, [userId, buttonId], (err) => {
                        if (err) {
                            return con.rollback(() => {
                                console.error('Error deleting button click record:', err);
                                res.status(500).json({ error: 'Failed to delete button click record' });
                            });
                        }

                        if (updateWeekTeamSql) {
                            // Update week_team if needed
                            con.query(updateWeekTeamSql, updateWeekTeamValues, (err) => {
                                if (err) {
                                    return con.rollback(() => {
                                        console.error('Error updating week_team:', err);
                                        res.status(500).json({ error: 'Failed to update week_team' });
                                    });
                                }

                                // Commit transaction
                                con.commit(err => {
                                    if (err) {
                                        return con.rollback(() => {
                                            console.error('Error committing transaction:', err);
                                            res.status(500).json({ error: 'Failed to commit transaction' });
                                        });
                                    }
                                    res.json({ status: 'success', message: 'Request approved, balance updated, and week_team adjusted' });
                                });
                            });
                        } else {
                            // Commit transaction if no week_team update is needed
                            con.commit(err => {
                                if (err) {
                                    return con.rollback(() => {
                                        console.error('Error committing transaction:', err);
                                        res.status(500).json({ error: 'Failed to commit transaction' });
                                    });
                                }
                                res.json({ status: 'success', message: 'Request approved, balance updated' });
                            });
                        }
                    });
                });
            });
        });
    });
});





// Reject salary request
app.post('/reject-salary-request', (req, res) => {
    const { requestId } = req.body;

    if (!requestId) {
        return res.status(400).json({ error: 'Request ID is required' });
    }

    const updateWeekBonusHistorySql = `
        UPDATE week_bonus_history
        SET approved = 2
        WHERE id = ?
    `;

    con.query(updateWeekBonusHistorySql, [requestId], (err) => {
        if (err) {
            console.error('Error updating week_bonus_history:', err);
            return res.status(500).json({ error: 'Failed to reject request' });
        }

        res.json({ status: 'success', message: 'Request rejected successfully' });
    });
});

app.post('/approve-withdrawal', async (req, res) => {
    const { userId, requestId, amount } = req.body;

    if (!userId || !requestId || !amount) {
        return res.status(400).json({ error: 'User ID, request ID, and amount are required' });
    }

    const updateWithdrawalRequestsSql = `
        UPDATE withdrawal_requests 
        SET approved = 'approved',  approved_time = CURRENT_TIMESTAMP 
        WHERE id = ? AND user_id = ?`;

    const updateUserBalanceAndTotalWithdrawalSql = `
        UPDATE users
        SET balance = 0,
            total_withdrawal = total_withdrawal + ?,
            withdrawalAttempts = withdrawalAttempts + 1,
            last_wallet_update = null
        WHERE id = ?`;

    const deleteUserClicksSql = `
        DELETE FROM user_product_clicks
        WHERE user_id = null`;

    const deleteReferralsSql = `
        DELETE FROM referrals
        WHERE referrer_id = ?
        LIMIT 5`;

    const insertNotificationSql = `
        INSERT INTO notifications (user_id, msg)
        VALUES (?, 'Withdraw Approved Successfully')
    `;

    con.beginTransaction(error => {
        if (error) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        con.query(updateWithdrawalRequestsSql, [requestId, userId], (error, results) => {
            if (error) {
                return con.rollback(() => {
                    res.status(500).json({ error: 'Internal Server Error' });
                });
            }

            if (results.affectedRows === 0) {
                return res.status(400).json({ error: 'Could not find the withdrawal request or it is already approved' });
            }

            con.query(updateUserBalanceAndTotalWithdrawalSql, [amount, userId], (error, results) => {
                if (error) {
                    return con.rollback(() => {
                        res.status(500).json({ error: 'Internal Server Error' });
                    });
                }

                con.query(deleteUserClicksSql, [userId], (error, results) => {
                    if (error) {
                        return con.rollback(() => {
                            res.status(500).json({ error: 'Internal Server Error' });
                        });
                    }

                    con.query(deleteReferralsSql, [userId], (error, deleteResult) => {
                        if (error) {
                            return con.rollback(() => {
                                res.status(500).json({ status: 'error', error: 'Failed to delete referrals' });
                            });
                        }

                        con.query(insertNotificationSql, [userId], (error, insertResult) => {
                            if (error) {
                                return con.rollback(() => {
                                    res.status(500).json({ error: 'Internal Server Error' });
                                });
                            }

                            con.commit(error => {
                                if (error) {
                                    return con.rollback(() => {
                                        res.status(500).json({ error: 'Failed to commit transaction' });
                                    });
                                }

                                res.json({ message: 'Withdrawal request approved, balance and total withdrawal updated, user clicks data, and referrals deleted successfully!' });
                            });
                        });
                    });
                });
            });
        });
    });
});
app.post('/give-bonus', (req, res) => {
    const adminId = 1;
    
    // Query to check if button was clicked today
    const checkClickQuery = `
        SELECT 1 FROM bonus_button_clicks 
        WHERE admin_id = ? AND DATE(clicked_at) = CURDATE()
    `;

    // Query to log button click
    const logButtonClickQuery = `
        INSERT INTO bonus_button_clicks (admin_id) VALUES (?)
    `;

    // Query to update bonuses
    const bonusQuery = `
        UPDATE users u
        JOIN (
            SELECT
                u.id AS user_id,
                bs.reward
            FROM
                users u
            JOIN (
                SELECT 
                    u2.refer_by,
                    COUNT(u2.id) AS referred_count
                FROM 
                    users u2
                WHERE 
                    u2.approved_at IS NOT NULL 
                    AND DATE(u2.approved_at) = CURDATE()
                GROUP BY 
                    u2.refer_by
            ) AS referrals ON u.id = referrals.refer_by
            JOIN bonus_settings bs 
                ON referrals.referred_count >= bs.need_refferer
                AND NOT EXISTS (
                    SELECT 1
                    FROM bonus_settings bs2
                    WHERE bs2.need_refferer > bs.need_refferer
                    AND referrals.referred_count >= bs2.need_refferer
                )
        ) AS reward_data ON u.id = reward_data.user_id
        SET u.balance = COALESCE(u.balance, 0) + reward_data.reward;
    `;

    // Start transaction
    con.beginTransaction((err) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Transaction start failed' });
        }

        // Check if the button was clicked today
        con.query(checkClickQuery, [adminId], (err, results) => {
            if (err) {
                console.log(err);
                return con.rollback(() => {
                    res.status(500).json({ status: 'error', error: 'Error checking button click' });
                });
            }

            // If button was clicked today, prevent further clicks
            if (results.length > 0) {
                return con.rollback(() => {
                    res.status(400).json({ status: 'error', error: 'Button can only be clicked once per day' });
                });
            }

            // Log button click if not clicked today
            con.query(logButtonClickQuery, [adminId], (err) => {
                if (err) {
                    console.log(err);
                    return con.rollback(() => {
                        res.status(500).json({ status: 'error', error: 'Failed to log button click' });
                    });
                }

                // Execute the bonus update query
                con.query(bonusQuery, (err, result) => {
                    if (err) {
                        console.log(err);
                        return con.rollback(() => {
                            res.status(500).json({ status: 'error', error: 'Today Boonus is Already Given' });
                        });
                    }

                    // Commit transaction
                    con.commit((err) => {
                        if (err) {
                            return con.rollback(() => {
                                res.status(500).json({ status: 'error', error: 'Failed to commit transaction' });
                            });
                        }
                        res.json({ status: 'success' });
                    });
                });
            });
        });
    });
});


app.get('/bonus-settings', (req, res) => {
    const fetchSettingsQuery = 'SELECT * FROM bonus_settings';
    
    con.query(fetchSettingsQuery, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch bonus settings' });
        }
        
        // If data fetched successfully, return it in the response
        res.json({ status: 'success', data: result });
    });
});
app.put('/bonus-settings/:id', (req, res) => {
    const settingId = req.params.id;
    const { need_refferer, reward } = req.body;
    
    const updateSettingQuery = `
        UPDATE bonus_settings
        SET need_refferer = ?, reward = ?
        WHERE id = ?
    `;

    con.query(updateSettingQuery, [need_refferer, reward, settingId], (err, result) => {
        if (err) {
            console.log(err);
            return res.status(500).json({ status: 'error', error: 'Failed to update bonus setting' });
        }

        res.json({ status: 'success', message: 'Bonus setting updated successfully' });
    });
});
app.get('/getUserAccount/:userId', (req, res) => {
    const user_id = req.params.userId;
      if (!user_id) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }
     let fetchQuery = 'SELECT * FROM users_accounts WHERE user_id = ?';
     let queryParams = [user_id];
     con.query(fetchQuery, queryParams, (err, result) => {
         if (err) {
             console.error('Error fetching user account:', err);
             return res.status(500).json({ status: 'error', error: 'Failed to fetch user account' });
         }
         if (result.length === 0) {
             return res.status(404).json({ status: 'error', message: 'User account not found' });
         }
         res.json({ status: 'success', userAccount: result[0] });
         console.log(result[0]);
         
     })
});

app.put('/updateHolderNumber', (req, res) => {
    const { coin_address, userId } = req.body;

    // Validate inputs
    if (!coin_address || !userId) {
        return res.status(400).json({ success: false, message: 'Holder number and user ID are required.' });
    }

    const sql = 'UPDATE users_accounts SET coin_address = ? WHERE user_id = ?';
    const values = [coin_address, userId];

    // Execute the query
    con.query(sql, values, (err, result) => {
        if (err) {
            console.error('Failed to update holder number:', err);
            return res.status(500).json({ success: false, message: 'Failed to update holder number.' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        res.json({ success: true, message: 'Holder number updated successfully.' });
    });
});

app.post('/reject-withdrawal', async (req, res) => {
    const { requestId, userId } = req.body; 

    if (!requestId || !userId) {
        return res.status(400).json({ error: 'Request ID and User ID are required' });
    }

    const updateWithdrawalRequestsSql = `
        UPDATE withdrawal_requests 
        SET reject=1, approved='rejected', reject_at=CURRENT_TIMESTAMP 
        WHERE id=? AND user_id=? ;
    `;

    try {
        con.query(updateWithdrawalRequestsSql, [requestId, userId], (err, result) => {
            if (err) {
                console.error('Error executing query', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            if (result.affectedRows > 0) {
                return res.json({ message: 'Withdrawal request rejected successfully!' });
            } else {
                return res.status(404).json({ error: 'No matching withdrawal request found' });
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.get('/withdrawalRequestsApproved', (req, res) => {
    const sql = 'SELECT * FROM withdrawal_requests WHERE approved = "approved" && reject = 0';

    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved withdrawal requests' });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: 'error', message: 'No approved withdrawal requests found' });
        }

        res.json({ status: 'success', data: results });
    });
});
app.get('/withdrawalRequestsRejected', (req, res) => {
    const sql = 'SELECT * FROM withdrawal_requests WHERE approved = "rejected"';

    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved withdrawal requests' });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: 'error', message: 'No approved withdrawal requests found' });
        }

        res.json({ status: 'success', data: results });
    });
});
app.get('/products', (req, res) => {
    const sql = 'SELECT * FROM products';
    
    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the products.' }); 
        }

        res.status(200).json({ success: true, data: results });
    });
});
app.get('/fetchClickedProducts', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ status: 'error', error: 'User not authenticated' });
    }

    const userId = req.session.userId;
    const today = new Date().toISOString().split('T')[0]; 

    const getClickedProductsSql = `
             SELECT p.*, upc.last_clicked
        FROM products p
        LEFT JOIN user_product_clicks upc 
        ON p.id = upc.product_id AND upc.user_id = ?
    `;

    con.query(getClickedProductsSql, [userId], (err, productResults) => {
        if (err) {
            console.error('Fetch clicked products query error:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch clicked products' });
        }

        const products = productResults.map(product => ({
            ...product,
            canClick: !product.last_clicked || new Date(product.last_clicked).toISOString().split('T')[0] !== today
        }));

        const productCount = products.length;

        if (productCount > 0) {
            const updateWalletSql = `
              UPDATE users
SET 
    today_wallet = CASE
        WHEN COALESCE(last_wallet_update, '') <> ? THEN (backend_wallet * 0.1 / ?)
        ELSE today_wallet
    END,
    backend_wallet = CASE
        WHEN COALESCE(last_wallet_update, '') <> ? THEN backend_wallet - backend_wallet * 0.1
        ELSE backend_wallet
    END,
    last_wallet_update = CASE
        WHEN COALESCE(last_wallet_update, '') <> ? THEN ?
        ELSE last_wallet_update
    END
WHERE id = ? AND (COALESCE(last_wallet_update, '') <> ?)
            `;

            con.query(updateWalletSql, [today, productCount, today, today, today, userId, today], (err) => {
                if (err) {
                    console.error('Update wallet query error:', err);
                    return res.status(500).json({ status: 'error', error: 'Failed to update wallet' });
                }

                const getUserDataSql = 'SELECT today_wallet FROM users WHERE id = ?';
                con.query(getUserDataSql, [userId], (err, userResults) => {
                    if (err) {
                        console.error('Fetch user wallet query error:', err);
                        return res.status(500).json({ status: 'error', error: 'Failed to fetch user data' });
                    }

                    const today_wallet = userResults[0]?.today_wallet || 0;
                    res.json({ 
                        status: 'success', 
                        products,
                        today_wallet 
                    });
                });
            });
        } else {
            res.json({ 
                status: 'success', 
                products: [],
                today_wallet: 0 
            });
        }
    });
});


app.post('/products', (req, res) => {
    const { description, link, reward, imgLink } = req.body;
    console.log(req.body);
    if (!description || !link  || !imgLink) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    const product = { description, link,  imgLink };
    const sql = 'INSERT INTO products SET ?';

    con.query(sql, product, (err, result) => {
        if (err) {
            console.log(err);

            return res.status(500).json({ success: false, message: 'An error occurred while adding the product.' }

            );

        }
        res.status(201).json({ success: true, message: 'Product added successfully.' });
    });
});

app.delete('/products/:id', (req, res) => {
    const id = req.params.id;

    if (!id) {
        return res.status(400).json({ success: false, message: 'ID is required.' });
    }

    const sql = 'DELETE FROM products WHERE id = ?';
    con.query(sql, [id], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while deleting the product.' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Product not found.' });
        }

        res.status(200).json({ success: true, message: 'Product deleted successfully.' });
    });
});

app.put('/products/:id', (req, res) => {
    const id = req.params.id;
    const { description, link,  imgLink } = req.body;
console.log(req.body);
    if (!description || !link  || !imgLink) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    const sql = 'UPDATE products SET description = ?, link = ?,  imgLink = ? WHERE id = ?';

    con.query(sql, [description, link, imgLink, id], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while updating the product.' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Product not found.' });
        }

        res.status(200).json({ success: true, message: 'Product updated successfully.' });
    });
});

app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    let sql = `SELECT * FROM users WHERE id = ${con.escape(userId)}`;
    con.query(sql, (err, result) => {
        if (err) {
            res.status(500).send(err);
            return;
        }

        if (result.length === 0) {
            res.status(404).send({ message: 'User not found' });
            return;
        }

        res.send(result[0]);
    });
});




app.get('/get-accounts', (req, res) => {
    const sql = 'SELECT * FROM accounts'; 

    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching accounts.' });
        }

        res.status(200).json({ success: true, accounts: results });
    });
});
app.get('/receive-accounts', (req, res) => {
    const status = 'on'; 
    const sql = 'SELECT * FROM accounts WHERE status = ? LIMIT 1'; 

    con.query(sql, [status], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching accounts.' });
        }

        if (result.length > 0) {
            res.status(200).json({ success: true, account: result[0] });
        } else {
            res.status(404).json({ success: false, message: 'No account found with the given status.' });
        }
    });
});

app.get('/get-fee', (req, res) => {
    // Query to get the joining_fee
    const feeSql = 'SELECT joining_fee FROM joining_fee WHERE id = ?';
    const accountId = 1;

    con.query(feeSql, [accountId], (feeErr, feeResult) => {
        if (feeErr) {
            console.error('Error fetching fee:', feeErr);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the fee.' });
        }

        if (feeResult.length > 0) {
            const feeValue = feeResult[0].joining_fee;

            // Now, query the usd_rate table to get the rate
            const rateSql = 'SELECT rate FROM usd_rate LIMIT 1'; // Assuming there's only one row
            con.query(rateSql, (rateErr, rateResult) => {
                if (rateErr) {
                    console.error('Error fetching rate:', rateErr);
                    return res.status(500).json({ success: false, message: 'An error occurred while fetching the rate.' });
                }

                if (rateResult.length > 0) {
                    const rate = rateResult[0].rate;
                    const feeInPkr = feeValue * rate; // Multiply fee by rate

                    res.status(200).json({ success: true, fee: feeValue, feeInPkr: feeInPkr.toFixed(0) });
                } else {
                    res.status(404).json({ success: false, message: 'No rate found in the usd_rate table.' });
                }
            });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});


app.get('/get-percentage', (req, res) => {
    const sql = 'SELECT initial_percent FROM initial_fee WHERE id = 1'; 
    con.query(sql, (err, result) => {
         if (err) {
            console.error('Error fetching fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the fee.' });
        }
         else{
            if (result.length > 0) {
                const feeValue = result[0].initial_percent;
                res.status(200).json({ success: true, initial_percent: feeValue });
            } else {
                res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
            }
         }
    })

  
});

app.get('/get-rate', (req, res) => {
    const sql = 'SELECT rate FROM usd_rate WHERE id = ?'; 

    const accountId = 1;

    con.query(sql, [accountId], (err, result) => {
        if (err) {
            console.error('Error fetching fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the fee.' });
        }

        if (result.length > 0) {
            const rateValue = result[0].rate;
            res.status(200).json({ success: true, rate: rateValue });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});


app.post('/update-fee', (req, res) => {
    const { newFeeValue } = req.body;

    const accountId = 1;

    const updateSql = 'UPDATE joining_fee SET joining_fee = ? WHERE id = ?';

    con.query(updateSql, [newFeeValue, accountId], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Fee updated successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});


app.post('/update-percentage', (req, res) => {
    const { newFeeValue } = req.body;

    const accountId = 1;

    const updateSql = 'UPDATE initial_fee   SET initial_percent = ? WHERE id = 1';

    con.query(updateSql, [newFeeValue, accountId], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Fee updated successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});
app.get('/pending-users', (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.perPage) || 10;
    const searchTerm = req.query.searchTerm || '';

    const offset = (page - 1) * perPage;

    let sql = 'SELECT * FROM users WHERE payment_ok = 0 AND approved = 0';

    if (searchTerm) {
        sql += ` AND (name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%' OR id = '${searchTerm}')`;
    }

    sql += ` LIMIT ? OFFSET ?`;

    const countSql = `SELECT COUNT(*) AS totalCount FROM users WHERE payment_ok = 0 AND approved = 0 ${searchTerm ? `AND (name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%' OR id = '${searchTerm}')` : ''}`;

    con.query(sql, [perPage, offset], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the pending users.' });
        }

        con.query(countSql, (countErr, countResult) => {
            if (countErr) {
                return res.status(500).json({ success: false, message: 'An error occurred while fetching total count.' });
            }

            const totalCount = countResult[0].totalCount;

            res.status(200).json({
                success: true,
                pendingUsers: result,
                totalCount: totalCount,
                currentPage: page,
                totalPages: Math.ceil(totalCount / perPage)
            });
        });
    });
});

app.post('/update-usd', (req, res) => {
    const { newFeeValue } = req.body;

    const accountId = 1; 

    const updateSql = 'UPDATE usd_rate SET rate = ? WHERE id = ?';

    con.query(updateSql, [newFeeValue, accountId], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Fee updated successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});
app.post('/update-offer', (req, res) => {
    const { newOfferValue } = req.body;

    const accountId = 1; 

    const updateSql = 'UPDATE offer SET offer = ? WHERE id = ?';

    con.query(updateSql, [newOfferValue, accountId], (err, result) => {
        if (err) {
            console.error('Error updating fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while updating the fee.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'Fee updated successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});


app.delete('/delete-user/:id', (req, res) => {
    const userId = req.params.id;
    const sql = 'DELETE FROM users WHERE id = ?';

    con.query(sql, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while deleting the user.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'User deleted successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'User not found.' });
        }
    });
});
app.delete('/delete-7-days-old-users', (req, res) => {
    const sql = `
        DELETE FROM users 
        WHERE payment_ok=0 AND approved=0 AND created_at <= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
    `;

    con.query(sql, (err, result) => {
        if(err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "An error occurred while deleting the users." });
        }

        res.status(200).json({ success: true, message: `${result.affectedRows} users deleted successfully.` });
    });
});

  
  
  app.post('/upload', upload.single('image'), (req, res) => {
  
    const {filename, path: filePath, size} = req.file;
    const uploadTime = new Date();
  
    const query = 'INSERT INTO images (file_name, file_path, upload_time) VALUES (?, ?, ?)';
    const values = [filename, filePath, uploadTime];
  
    con.query(query, values, (error, results, fields) => {
      if (error) throw error;
  
      res.json({ message: 'File uploaded and data saved successfully' });
    });
  });
  app.get('/getImage', (req, res) => {
    const query = 'SELECT * FROM images ORDER BY upload_time DESC LIMIT 1';
  
    con.query(query, (error, results, fields) => {
      if (error) {
        console.error(error);
        return res.status(500).json({ error: 'An error occurred while fetching image data' });
      }
  
      if (results.length > 0) {
        res.json(results[0]);
      } else {
        res.status(404).json({ message: 'No images found' });
      }
    });
  });

app.post('/update-accounts', (req, res) => {
    const accounts = req.body.accounts;

    if (!accounts || !Array.isArray(accounts)) {
        return res.status(400).json({ success: false, message: 'Invalid account data.' });
    }

    accounts.forEach(account => {
        if (account.account_id) {  
            const sql = 'UPDATE accounts SET account_name = ?, account_number = ?, status = ? WHERE account_id = ?';
            const values = [account.account_name, account.account_number, account.status, account.account_id];

            con.query(sql, values, (err) => {
                if (err) {
                    console.error('Failed to update account:', err);
                }
            });
        } else {
            console.error('Account ID is NULL, skipping update.');
        }
    });

    res.json({ success: true, message: 'Accounts updated successfully.' });
});



app.get('/get-total-withdrawal', (req, res) => {
    const sql = 'SELECT SUM(amount) AS totalWithdrawal FROM withdrawal_requests';

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the total withdrawal.' });
        }

        if (result.length === 0) {
            return res.status(404).json({ success: false, message: 'No withdrawal requests found.' });
        }

        res.status(200).json({ success: true, totalWithdrawal: result[0].totalWithdrawal });
    });
});
app.delete('/delete-old-rejected-users', (req, res) => {
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const deleteOldRejectedUsersSql = `
        DELETE FROM users
        WHERE rejected = 1 AND rejected_at < ?`;

    con.query(deleteOldRejectedUsersSql, [sevenDaysAgo], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        res.json({ message: 'Old rejected user records deleted successfully' });
    });
});
app.delete('/delete-rejected-users', (req, res) => {
    const deleteRejectedUsersSql = `
        DELETE FROM users
        WHERE rejected = 1`;

    con.query(deleteRejectedUsersSql, (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (results.affectedRows === 0) {
            return res.json({ message: 'No rejected users to delete' });
        }

        res.json({ message: 'Rejected users deleted successfully' });
    });
});


app.get('/unapproved-unpaid-users-count', (req, res) => {
    const sql = 'SELECT COUNT(*) AS count FROM users WHERE payment_ok = 0 AND approved = 0';

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the users count.' });
        }

        if (result.length === 0) {
            return res.status(404).json({ success: false, message: 'No users found.' });
        }

        res.status(200).json({ success: true, count: result[0].count });
    });
});




  const fetchApprovedUserNames = (referByUserId) => {
    return new Promise((resolve, reject) => {
      const fetchNamesQuery = 'SELECT id, name , approved_at FROM users WHERE refer_by = ? AND approved = 1';
      con.query(fetchNamesQuery, [referByUserId], (err, results) => {
        if (err) {
          reject(err);
        } else {
          resolve(results);
        }
      });
    });
  };
  
  
  app.get('/approvedUserNames/:referByUserId', async (req, res) => {
    const { referByUserId } = req.params;
  
    try {
      const users = await fetchApprovedUserNames(referByUserId);
      res.json({ status: 'success', users });
    } catch (error) {
      console.error('Error fetching approved users:', error);
      res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
    }
  });




  app.post('/payment', (req, res) => {
    const { trx_id, sender_name, sender_number, id } = req.body;
    const payment_ok = 1;
    const rejected = 0;

    // Check if the trx_id already exists in the users table
    const checkQuery = 'SELECT COUNT(*) AS count FROM users WHERE trx_id = ?';
    con.query(checkQuery, [trx_id], (checkErr, checkResults) => {
        if (checkErr) {
            return res.status(500).json({ status: 'error', error: 'Database error' });
        }

        // Inside the '/payment' route
        if (checkResults[0].count > 0) {
            // The trx_id already exists; return an error response
            return res.status(400).json({ status: 'error', error: 'Transaction ID already in use' });
        }


        // The trx_id doesn't exist; update the user's payment data
        const sql = 'UPDATE users SET trx_id = ?, sender_name = ?, sender_number = ?, payment_ok = ?, rejected = ? WHERE id = ?';

        con.query(sql, [trx_id, sender_name, sender_number, payment_ok, rejected, id], (err, result) => {
            if (err) {
                return res.status(500).json({ status: 'error', error: 'Failed to update payment data' });
            }

            res.json({ status: 'success' });
        });
    });
});

app.get('/dashboard-data', (req, res) => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const tomorrow = new Date(today);
    tomorrow.setDate(today.getDate() + 1);

    const firstDayOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);
    const lastDayOfMonth = new Date(today.getFullYear(), today.getMonth() + 1, 0);

    const sql = `
        SELECT 
            (SELECT COUNT(*) FROM users WHERE approved = 1 AND id NOT BETWEEN 5199 AND 5205) as approvedUsersCount,
            (SELECT COUNT(*) FROM users WHERE approved = 1 AND approved_at >= ? AND approved_at < ? AND id NOT BETWEEN 5199 AND 5200) as approvedUsersCountToday,
            (SELECT SUM(amount) FROM withdrawal_requests WHERE approved='approved' AND user_id NOT BETWEEN 5199 AND 5205) as totalWithdrawal,
            (SELECT SUM(amount) FROM withdrawal_requests WHERE approved = 'approved' AND approved_time >= ? AND approved_time < ?) as totalAmountToday,
            (SELECT COUNT(*) FROM users WHERE payment_ok = 0 AND approved = 0 AND id NOT BETWEEN 5199 AND 5205) as unapprovedUnpaidUsersCount,
            (SELECT SUM(jf.joining_fee) FROM joining_fee jf JOIN users u ON u.approved = 1 AND u.id NOT BETWEEN 1 AND 10) as totalReceived,
            (SELECT SUM(jf.joining_fee) FROM joining_fee jf JOIN users u ON u.approved = 1 AND approved_at >= ? AND approved_at < ? AND u.id NOT BETWEEN 5199 AND 5200) as totalReceivedToday,
            (SELECT SUM(amount) FROM withdrawal_requests WHERE approved = 'approved' AND approved_time >= ? AND approved_time <= ?) as totalAmountThisMonth,
            (SELECT SUM(jf.joining_fee) FROM joining_fee jf JOIN users u ON u.approved = 1 AND approved_at >= ? AND approved_at <= ? AND u.id NOT BETWEEN 5199 AND 5200) as totalReceivedThisMonth
    `;

    con.query(sql, [today, tomorrow, today, tomorrow, today, tomorrow, firstDayOfMonth, lastDayOfMonth, firstDayOfMonth, lastDayOfMonth], (err, results) => {
        if (err) {
            console.log(err);

            return res.status(500).json({ success: false, message: 'An error occurred while fetching dashboard data.' });
            
        }

        const dashboardData = {
            approvedUsersCount: results[0].approvedUsersCount,
            approvedUsersCountToday: results[0].approvedUsersCountToday,
            totalWithdrawal: results[0].totalWithdrawal,
            totalAmountToday: results[0].totalAmountToday,
            unapprovedUnpaidUsersCount: results[0].unapprovedUnpaidUsersCount,
            totalReceived: results[0].totalReceived,
            totalReceivedToday: results[0].totalReceivedToday,
            totalAmountThisMonth: results[0].totalAmountThisMonth,
            totalReceivedThisMonth: results[0].totalReceivedThisMonth
        };

        res.status(200).json({ success: true, dashboardData });
    });
});

https.createServer(options, app).listen(PORT, () => {
  console.log('HTTPS Server running on port '+PORT);
});
