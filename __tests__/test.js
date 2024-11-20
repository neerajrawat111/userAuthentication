const chai = require('chai');
const chaiHttp = require('chai-http');
const app = require('../index');
const { prisma } = require('../db/config');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { expect } = chai;
chai.use(chaiHttp);
const { JWT_SECRET } = require('../constants/constant.js');

describe('Auth Routes', () => {
  let userId;
  before(async () => {
    await prisma.user.deleteMany();
    await prisma.user.create({
      data: {
        id: 1,
        name: 'logan',
        email: 'logan@gmail.com',
        password: await bcrypt.hash('logan123', 10) // Assuming bcrypt is used
      }
    });
  });
  after(async () => {
    await prisma.$disconnect();
  });

  it('should create account for a given user', (done) => {
    const newUser = {
        name: "logan",
        email: "logan12@gmail.com",
        password : "logan1234"
    }; 
    chai
      .request(app)
      .post('/api/auth/signup')
      .send(newUser)
      .end(async (err, res) => {
        expect(res).to.have.status(201);
        expect(res.body).to.be.an('object');
        expect(res.body).to.include(newUser);
        expect(res.body.email).to.be.equal(newUser.email)
        userId = res.body.userId; 

        // Verify in database
        const userInDb = await prisma.user.findUnique({
          where: { userId: parseInt(res.body.userId) },
        });
        expect(userInDb).to.include(newUser);
      });
      done();
    });
    
    it('should return 400 if the email is already in use', (done) => {
      const existingUser = {
        name: "logan",
        email: "logan@gmail.com", // Email already exists in the database
        password: "logan123"
      };
    
      chai
        .request(app)
        .post('/api/auth/signup')
        .send(existingUser)
        .end((err, res) => {
          expect(res).to.have.status(400);
          expect(res.body).to.be.an('object');
          expect(res.body).to.have.property('error', 'Email already in use');
          done();
        });
    });
    

// Test for attempting to sign up with null data
it('should return 400 when trying to create an account with null data', (done) => {
    const newUser=null;
    chai
      .request(app)
      .post('/api/auth/signup')
      .send(newUser)
      .end((err, res) => {
        expect(res).to.have.status(400);
        expect(res.body).to.be.an('object');
        expect(res.body).to.have.property('error', 'Name, email, and password are required');
        done();
      });
  });
});

// login

describe('Login Tests', () => {
    it('should log in successfully with valid credentials', (done) => {
      const data = {
        email: "logan@gmail.com",
        password: "logan123"
      };
      
      chai
        .request(app)
        .post('/api/auth/login')
        .send(data)
        .end((err, res) => {
          expect(res).to.have.status(200);
          expect(res.body).to.be.an('object');
          expect(res.body).to.have.property('userdata');
          expect(res.body.userdata).to.have.property('id');
          expect(res.body.userdata).to.have.property('name');
          expect(res.body.userdata).to.have.property('email');
          expect(res.body).to.have.property('accesstoken');
          const token = res.body.accesstoken;
          try {
            const decoded = jwt.verify(token, JWT_SECRET);
            expect(decoded).to.be.an('object');
            expect(decoded).to.have.property('userId', 1);
          } catch (error) {
            throw new Error(`Token verification failed: ${error.message}`);
          }
          done();
        });
    });
  
    it('should return 400 if email or password is missing', (done) => {
      chai
        .request(app)
        .post('/api/auth/login')
        .send({ email: "logan@gmail.com" }) // Password is missing
        .end((err, res) => {
          expect(res).to.have.status(400);
          expect(res.body).to.be.an('object');
          expect(res.body).to.have.property('error', 'Email and password are required');
          done();
        });
    });
    it('should return 401 if the password is incorrect', (done) => {
      const invalidCredentials = {
        email: "logan@gmail.com", // Correct email
        password: "wrongpassword" // Incorrect password
      };
    
      chai
        .request(app)
        .post('/api/auth/login')
        .send(invalidCredentials)
        .end((err, res) => {
          expect(res).to.have.status(401);
          expect(res.body).to.be.an('object');
          expect(res.body).to.have.property('error', 'Invalid credentials');
          done();
        });
    });
  });