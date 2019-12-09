const Tour = require('./../models/tourModel');
const APIFeatures = require('./../utils/apiFeatures');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');
exports.aliasTopTours = (req, res, next) => {
    req.query.limit = '5';
    req.query.sort = '-ratingsAverage,price';
    //req.query.fields = 'name';
    next();
  };

 

//const tours = JSON.parse(fs.readFileSync(`${__dirname}/../dev-data/data/tours-simple.json`));

/* exports.checkID = (req, res, next, val) => {
    console.log(`Tour id is: ${val}`);
  
    if (req.params.id * 1 > tours.length) {
      return res.status(404).json({
        status: 'fail',
        message: 'Invalid ID'
      });
    }
    next();
};*/

/*exports.checkBody=(req,res,next)=>{
    if(!req.body.name || !req.body.price)
    {
        return res.status(404).json({
            status: 'fails',
            message: 'missing price and name'
        });
    }
    next();

}*/

exports.createTour =catchAsync(async (req,res,next)=>{
 /*   const newId = tours[tours.length -1].id +1 ; 
    const newTour = Object.assign({id: newId},req.body);
    tours.push(newTour);
    fs.writeFile(`${__dirname}/dev-data/data/tours-simple.json`,JSON.stringify(tours),err =>{
        res.status(201).json({
            status:'sucess',
            data : {
              tours : newTour
            }
        });
    });*/
    const newTour = await Tour.create(req.body);
    res.status(201).json({
        status:'sucess',
        data : {
          tours : newTour
        }
    });
    // try{
    //     const newTour = await Tour.create(req.body);
    // res.status(201).json({
    //     status:'sucess',
    //     data : {
    //       tours : newTour
    //     }
    // });
    //     }catch (err){
    //         res.status(400).json({
    //             status:'fail',
    //             message:err
    //         });
    //     }
 
});

exports.getTour = catchAsync(async (req, res,next) => {
   // console.log(req.params);
    //const id = req.params.id * 1;
  
  //  const tour = tours.find(el => el.id === id);
   /* if(!tour)
    {
        return res.status(404).json({
            status:'fail',
            message:'invalid id'
        });
    }*/
  
   // res.status(200).json({
   //   status: 'success',
    //  data: {
    //    tour
    //  }
   // });
   //try{
   const tour = await Tour.findById(req.params.id).populate('reviews');

   if(!tour){
       return next(new AppError('no tour found with that id',404))
   }
   res.status(200).json({
       status:'success',
       data:{
           tour
       }

   });
//    }catch (err) {
//        res.status(404).json({
//            status:'fail',
//            message:err
//        });

//    } 
  });

 exports.getAllTours = catchAsync(async (req,res,next)=>{
 //     try{
//          // filtering
//          const queryObj = {...req.query};
//         //  const excludedFields = ['page','sort','limit','fields'];
//         //  excludedFields.forEach(el => delete queryObj[el]);
//         // console.log(req.query,queryObj);
   
//         // //
//         // // advance filtering
//         //  let queryStr = JSON.stringify(queryObj);
//         //  queryStr = queryStr.replace(/\b(gt|gte|lt|lte)\b/g, match => `$${match}`);
//         //  //console.log(JSON.parse(queryStr));


//         // let query =  Tour.find(JSON.parse(queryStr));

//         // sorting the price
//         // if(req.query.sort)
//         // {
//         //     const sortBy = req.query.sort.split(',').join(' ');
//         //    // console.log(sortBy);
//         //     query = query.sort(sortBy);
//         // }else{
//         //     query = query.sort('-createdAt');
//         // }

//         //field limiting
//         // if(req.query.fields)
//         // {
//         //     let fields = req.query.fields.split(',').join(' ');
//         //     query = query.select(fields);
//         // }else
//         // {
//         //     query = query.select('-__v');
//         // }

//         // pagination 
//         // const page = req.query.page * 1 || 1;
//         // const limit = req.query.limit * 1 || 100;
//         // const skip =(page -1 ) * limit;

//         // query = query.skip(skip).limit(limit);

//         // if(req.query.page){
//         //     const numTours  = await Tour.countDocuments();
//         //     if(skip >= numTours) throw new  Error('This page is not found');
//         // }

         const features = new APIFeatures(Tour.find(),req.query)
         .filter()
         .sort()
         .limitFields()
         .paginate();
         const tours = await features.query;
    //const tours = await Tour.find()
//    //.where('duration')
//    //.equals(5)
//    //.where('difficulty')
//    //.equals('easy');
     res.status(200).json({
         result:tours.length,
         status: 'sucess',
         //requestTime : req.requestTime,
         data : {
            tours
         }
     });
    //  }catch (err)
    //  {
    //      res.status(404).json({
    //          status:'fail',
    //          message: err
    //      });
    //  }
 });
// exports.getAllTours = async (req, res) => {
//     try {
//       // EXECUTE QUERY
//       const features = new APIFeatures(Tour.find(), req.query)
//         .filter()
//         .sort()
//         .limitFields()
//         .paginate();
//       const tours = await features.query;
  
//       // SEND RESPONSE
//       res.status(200).json({
//         status: 'success',
//         results: tours.length,
//         data: {
//           tours
//         }
//       });
//     } catch (err) {
//       res.status(404).json({
//         status: 'fail',
//         message: err
//       });
//     }
//   };
exports.updateTour= catchAsync(async (req,res,next)=>{
    //try{
        const tour = await Tour.findByIdAndUpdate(req.params.id,req.body,{
            new : true,
            runValidators: true
        });
        if(!tour){
            return next(new AppError('no tour found with that id',404))
        }
    res.status(201).json({
        status:'sucess',
        data:{
            tour
        }
    });
// } catch (err)
// {
//     res.status(404).json({
//         status:'fail',
//         message:err
//     });
//}
});

exports.deleteTour = catchAsync(async (req, res,next) => {
    //try{
       const tour = await Tour.findByIdAndDelete(req.params.id);
        if(!tour){
            return next(new AppError('no tour found with that id',404))
        }

    res.status(204).json({
      status: 'success',
      data: null
    });
// }catch (err)
// {
//     res.status(404).json({
//         status:'fail',
//         message:err
//     });
// }
});

// exports.getTourStats = async (req,res) => {
//     try{
//         const stats = await Tour.aggregate([
//             {
//                 $match: { ratingsAverage : {$gte: 4.5} }
//             },
//             {
//                 $group: {
//                     _id:null,
//                     avgRating: {$avg: '$ratingsAverage'},
//                     avgPrice: {$avg: '$price'},
//                     minPrice: {$min: '$price'},
//                     maxPrice: {$max: '$price'}
//                 }
//             }
//         ]);

//         res.status(200).json({
//             status:'success',
//             data:{
//                 stats
//             }
//         });
//     }catch(err)
//     {
//         res.stats(404).json({
//             status:'fail',
//             message:err
//         });
//     }
// }; 

// under maintainces--- this part is under maintaince
exports.getTourStats = async (req, res) => {
    try {
      const stats = await Tour.aggregate([
        {
          $match: { startDates: { $gte: new Date(`2021-01-01`),
                                $lte: new Date('2021-12-31') } }
        },
        // {
        //   $group: {
        //     _id: { $toUpper: '$difficulty' },
        //     numTours: { $sum: 1 },
        //     numRatings: { $sum: '$ratingsQuantity' },
        //     avgRating: { $avg: '$ratingsAverage' },
        //     avgPrice: { $avg: '$price' },
        //     minPrice: { $min: '$price' },
        //     maxPrice: { $max: '$price' }
        //   }
        // },
        // {
        //   $sort: { avgPrice: 1 }
        // }
        // // {
        //   $match: { _id: { $ne: 'EASY' } }
        // }
      ]);
  
      res.status(200).json({
        status: 'success',
        data: {
          stats
        }
      });
    } catch (err) {
      res.status(404).json({
        status: 'fail',
        message: 'invalid response'
      });
    }
  };

  exports.getMonthlyPlan = catchAsync(async (req,res,next) => {
      //try{
        const year = req.params.year * 1;
        const plan  = await Tour.aggregate([
            {
                $unwind: '$startDates'
            },
             {
                 $match : { startDates:{
                     $gte: new Date(`${year}-01-01`),
                     $lte: new Date(`${year}-12-31`),
                 }
             }
            },
            {
                $group: {
                    _id: {$month: '$startDates'},
                    numTourStart : {$sum : 1},
                    tours:{$push:'$name'}
                }
            },
            {
                $addFields: { month: '$_id'}
            },
            {
                $project: {
                    _id: 0
                }
            },
            {
                $sort:{numTourStart: -1}
            }
            
        ]);
        res.status(200).json({
            status:'success',
            data:{
                plan
            }
        });
    //   }catch(err){
    //       res.status(404).json({
    //           status:'fails',
    //           message: err
    //       });

    //   }
  });
  