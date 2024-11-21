const chai = require('chai');
const chaiHttp = require('chai-http');
const app = require('../index');
const { prisma } = require('../db/config');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { expect } = chai;
chai.use(chaiHttp);
const { JWT_SECRET } = require('../constants/constant.js');


describe('SignUp Tests', () => {
  beforeEach(async () => {
    await prisma.user.deleteMany();
  });

  it('should create account for a given user', async () => {
    const newUser = {
      name: 'logan',
      email: 'logan12@gmail.com',
      password: 'logan1234',
    };

    // Send request to create a new user
    const res = await chai.request(app).post('/api/auth/signup').send(newUser);
    expect(res).to.have.status(201);
    expect(res.body).to.be.an('object');
    expect(res.body).to.have.property('userId');

    // Verify user in the database
    const userInDb = await prisma.user.findUnique({
      where: { id: res.body.userId },
    });
    expect(userInDb).to.exist;
    expect(userInDb.email).to.equal(newUser.email);

    // Check if password is hashed correctly
    const isPasswordValid = await bcrypt.compare(newUser.password, userInDb.password);
    expect(isPasswordValid).to.be.true;
  });

  it('should return 400 if email is missing', async () => {
    const userWithoutEmail = {
      name: 'logan',
      password: 'password123',
    };
  
    const res = await chai.request(app).post('/api/auth/signup').send(userWithoutEmail);
    expect(res).to.have.status(400);
    expect(res.body).to.be.an('object');
    expect(res.body).to.have.property('error');
  });
  
  it('should return 400 if password is missing', async () => {
    const userWithoutPassword = {
      name: 'logan',
      email: 'logan@gmail.com',
    };
  
    const res = await chai.request(app).post('/api/auth/signup').send(userWithoutPassword);
    expect(res).to.have.status(400);
    expect(res.body).to.be.an('object');
    expect(res.body).to.have.property('error');
  });

  it('should return 400 if the email is already in use', async () => {
    const existingUser = {
      name: 'logan',
      email: 'logan@gmail.com',
      password: await bcrypt.hash('logan123', 10),
    };
    await prisma.user.create({ data: existingUser });

    const duplicateUser = {
      name: 'logan',
      email: 'logan@gmail.com', 
      password: 'logan123',
    };

    const res = await chai.request(app).post('/api/auth/signup').send(duplicateUser);
    expect(res).to.have.status(400);
    expect(res.body).to.be.an('object');
    expect(res.body).to.have.property('error', 'Email already in use');
  });
  
});



// login

describe('Login Tests', () => {
  beforeEach(async () => {
    await prisma.user.deleteMany();
  })
  it('should log in successfully with valid credentials', async() => {

    const existingUser = {
      name: 'logan',
      email: 'logan@gmail.com',
      password: await bcrypt.hash('logan123', 10),
    };
    const createdUser= await prisma.user.create({ data: existingUser });
    
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
          expect(decoded).to.have.property('userId', createdUser.id);
        } catch (error) {
          throw new Error(`Token verification failed: ${error.message}`);
        }
      });
  });

  it('should return 400 if email or password is missing', () => {
    chai
      .request(app)
      .post('/api/auth/login')
      .send({ email: "logan@gmail.com" }) // Password is missing
      .end((err, res) => {
        expect(res).to.have.status(400);
        expect(res.body).to.be.an('object');
        expect(res.body).to.have.property('error', 'Email and password are required');
      });
  });

  it('should return 401 if the password is incorrect', async () => {
    const existingUser = {
      name: 'logan',
      email: 'logan@gmail.com',
      password: await bcrypt.hash('correctpassword', 10),
    };
    await prisma.user.create({ data: existingUser });
  
    const invalidCredentials = {
      email: 'logan@gmail.com',
      password: 'wrongpassword', // Incorrect password
    };
  
    const res = await chai.request(app).post('/api/auth/login').send(invalidCredentials);
    expect(res).to.have.status(401);
    expect(res.body).to.be.an('object');
    expect(res.body).to.have.property('error', 'Invalid credentials');
  });

  it('should return 404 if the user is not found', async () => {
    // Data for a non-existing user
    const nonExistingUser = {
      email: 'nonexistentuser@gmail.com',
      password: 'somepassword',
    };

    chai
      .request(app)
      .post('/api/auth/login')
      .send(nonExistingUser)
      .end((err, res) => {
        // Assert that the response status is 404 (User Not Found)
        expect(res).to.have.status(404);
        expect(res.body).to.be.an('object');
        expect(res.body).to.have.property('error', 'User not found');
      });
  });
});