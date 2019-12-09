const crypto = require('crypto');
const {promisify} = require('util');
const jwt = require('jsonwebtoken');
const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');
const sendEmail = require('./../utils/email');
const signToken = id =>{
    return jwt.sign({ id },process.env.JWT_SECRET,{
        expiresIn: process.env.JWT_EXPIRES_IN
});
};

const createSendToken = (user, statusCode,res) =>{
    const token = signToken(user._id);
    const cookieOptions = {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000),
    
        httpOnly: true
    };
    if(process.env.NODE_ENV === 'production') cookieOptions.secure = true; 
    res.cookie('jwt',token,cookieOptions);

    user.password = undefined;

    res.status(statusCode).json({
        status:'success',
        token,
        data:{
            user
        }
    });

}

exports.signup =catchAsync(async (req,res) =>{
    const newUser = await User.create(req.body);
  /*  name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
    role:req.body.role
    }); 
    */
   createSendToken(newUser, 201 ,res);
  /*  const token = signToken(newUser._id);

    res.status(201).json({
        status:'success',
        token,
        data:{
            user: newUser
        }
    }); */
});

exports.login =catchAsync(async(req,res,next)=>{
    const {email,password} = req.body;

    if(!email || !password)
    {
      return  next(new AppError('please enter the email and password',400));
    }

    const user = await User.findOne({ email }).select('+password');
   // const correct = user.correctPassword(password,user.password);
// checking the password is correct or not
if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }
  createSendToken(user,200,res);
   /* const token =signToken(user._id);
    res.status(200).json({
        status:'success',
        token
    });*/
});

exports.protect = catchAsync(async(req,res,next)=>{
    let token;
    if(req.headers.authorization && req.headers.authorization.startsWith('Bearer')){
     token = req.headers.authorization.split(' ')[1];
    }
//    console.log(token);

    if(!token)
    {
        return next(new AppError('you are not login please login',401));
    }

    const decoded = await promisify(jwt.verify)(token,process.env.JWT_SECRET);
    
    const currentUser =  await User.findById(decoded.id);

    if(!currentUser)
    {
        return next(new AppError('the token belonging to this user does not longer exit.',401));
    }

   if(currentUser.changePasswordAfter(decoded.iat))
   {
       return next(new AppError('User recently changed password! Please login again.',401));
   }

   //grant access the proceted routes
   req.user = currentUser; 

    next();
});

exports.restrictTo = (...roles) => {
    return (req,res,next) => {
        if(!roles.includes(req.user.role))
        {
            return next(new AppError('you do not have the permission to do this',403));
        }
        next();
    };
};
/*
 exports.forgotPassword = catchAsync(async (req,res,next) => {
    const user = await User.findOne({ email: req.body.email });
    if(!user)
    {
        return next(new AppError('There is no user with email address',404));
    }
    const resetToken = user.createPasswordResetToken();

    await user.save({validateBeforeSave: false});

    //const resetURL =`${req.protocol}://${req.get('host')}/api/v1/users/resetPassword/${resetToken}`;
    const resetURL = `${req.protocol}://${req.get(
     'host'
   )}/api/v1/users/resetPassword/${resetToken}`;
    // const message = `Forget your password ? submit PATCH request with your new password and passwordConfirm to:${resetURL}.\n
    // If you didn't forget your password then ignore this email`;
    const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;


    try
    {
    await sendEmail({
        email:user.email,
        subject: 'Your password reset Token(valid for only 10 min)',
        message
    });
    res.status(200).json({
        status:'success',
        message:'Token send to email'
    });
}catch(err)
{
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({validateBeforeSave:false});

    return next(new AppError('There is Some error in sending the mail So please try again Later!'),500);
}
 });*/
 exports.forgotPassword = catchAsync(async (req, res, next) => {
    // 1) Get user based on POSTed email
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return next(new AppError('There is no user with email address.', 404));
    }
  
    // 2) Generate the random reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });
  
    // 3) Send it to user's email
    const resetURL = `${req.protocol}://${req.get(
      'host'
    )}/api/v1/users/resetPassword/${resetToken}`;
  
    const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;
  
    try {
      await sendEmail({
        email: user.email,
        subject: 'Your password reset token (valid for 10 min)',
        message
      });
  
      res.status(200).json({
        status: 'success',
        message: 'Token sent to email!'
      });
    } catch (err) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });
  
      return next(
        new AppError('There was an error sending the email. Try again later!'),
        500
      );
    }
  });
  

exports.resetPassword = catchAsync(async(req,res,next) => {
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({passwordResetToken: hashedToken, passwordResetExpires:{ $gt:Date.now() } });

    if(!user)
    {
        return next(new AppError('Token is invalid or Token is Expired',400));
    }
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();
    createSendToken(user, 200 ,res);
    
   /* const token = signToken(user._id)
    res.status(200).json({
        status:'success',
        token
    }); */

});

exports.updatePassword = catchAsync(async(req,res,next) =>{
    const user = await User.findById(req.user.id).select('+password');

    if (!(await user.correctPassword(req.body.passwordCurrent, user.password)))
    {
        return next(new AppError('Your current Password is Wrong',401));
    }

    user.password =req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    await user.save();

    createSendToken(user, 200,res);

});