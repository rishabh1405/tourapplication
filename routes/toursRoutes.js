const express= require('express');
const tourController = require('./../controller/tourController');
const authController = require('./../controller/authController');
//const reviewController = require('./../controller/reviewController');
const reviewRouter = require('./../routes/reviewRoutes');

const router = express.Router();

router.use('/:tourID/reviews', reviewRouter);

router
  .route('/top-5-cheap')
  .get(tourController.aliasTopTours, tourController.getAllTours);

router.route('/tour-stats').get(tourController.getTourStats);

router.route('/monthly-plan/:year').get(tourController.getMonthlyPlan);
//router.param('id',tourController.checkID);

router
.route('/')
.get(authController.protect,tourController.getAllTours)
.post(tourController.createTour);

//get specific tours 

router
.route('/:id')
.get(tourController.getTour)
.patch(tourController.updateTour)
.delete(authController.protect, authController.restrictTo('admin','lead-guide'), tourController.deleteTour);

// router.route('/:tourID/reviews')
// .post(authController.protect,authController.restrictTo('user'),reviewController.createReview);


module.exports = router