
const express = require('express');
const app = express();
const morgan= require('morgan');
const route = express.Router();
const AppError = require('./utils/appError');
const globalErrorHandler = require('./controller/errorController');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');

const reviewRouter = require('./routes/reviewRoutes');
const tourRouter = require('./routes/toursRoutes');
const userRouter = require('./routes/userRoutes');

app.use(helmet());
//use of the middleware
if(process.env.NODE_ENV === 'development')
{
app.use(morgan('dev'));
}
const limiter = rateLimit({
    max: 100,
    windowMs: 60 * 60 * 1000,
    message: 'Too many Request from this IP, Please try again in an hour' 
});
app.use('/api',limiter);

//app.use(express.json({limit : '10kb' }))
app.use(express.json());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp({
    whitelist: ['duration','ratingQunatity','ratingAverage','maxGroupSize','difficulty','price']
})
);
app.use(express.static(`${__dirname}/public/`));


// reading the file from the top level 


app.use((req,res,next)=>{
    req.requestTime = new Date().toISOString();
   // console.log(req.headers);
    next();
});


//

//post route
app.use('/api/v1/tours',tourRouter);
app.use('/api/v1/users',userRouter);
app.use('/api/v1/reviews',reviewRouter);


app.all('*',(req,res,next)=>{
    // res.status(400).json({
    //     status:'fail',
    //     message:`invalid route ${req.originalUrl} on the server `
    
    // const err = new Error(`invalid route ${req.originalUrl} on the server`);
    // err.statusCode = 404,
    // err.status = 'fail'
    next(new AppError(`invalid route ${req.originalUrl} on the server`, 404));
});

app.use(globalErrorHandler);

module.exports = app;