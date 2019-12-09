const mongoose = require('mongoose');
const slugify = require('slugify');
const validator = require('validator');
//const User = require('./userModel');
const tourSchema = new mongoose.Schema(
    {
        name:{
            type:String,
            required:[true, 'A tours must have the name'],
            unique:true,
            trim:true,
            minlength:[40,'A tour must have less then or 40 charaters'],
            minlength:[4 ,'A tour must have more then 4 characters'],
          //  validate: [validator.isAlpha ,'Tour name only contain the character']
        },
        slug:String,
        duration:{
            type:Number,
            required:[true, 'A tour Must have the durations']
        },
        maxGroupSize: {
            type:Number,
            required:[true, 'A tour Must have the Group Size']
        },
        difficulty:{
            type:String,
            required:[true, 'A tour Must have the diffculty'],
            enum:
            {
               values: ['easy','medium','difficult'],
               message: 'only easy or medium or difficult field is added in the tours'
            }
        },

        ratingAverages:{
            type:Number,
            default:4.5,
            min:[1 ,'Rating must above 1.0'],
            max:[5, 'Rating must less then 5.0']
        },
        ratingQuantity:{
            type:Number,
            default:0
        },
        price:{
            type:Number,
            required:[true,'Price of Tours must be Given']
        },
        priceDiscount:
        {
            type:Number,
            validate:{
            validator: function(val){
                return val< this.price;
            },
            message:"Discount price ({VALUE}) must be less then actual price"
        }
         },
        summary:{
            type:String,
            trim:true,
            required:[true,'A tour must have the description']

        },
        description:{
            type:String,
            trim:true

        },
        imageCover:{
            type:String,
            required:[true,'A tour must have the Images']
        },
        images: [String],
        createdAt:{
            type:Date,
            default:Date.now(),
            select :false
        },
        startDates:[Date],
        secretTour: {
            type: Boolean,
            default: false
        },
        startLocation:{
            //geojson 
            type:{
                type: String,
                default: 'Point',
                enum: ['Point']
            },
            coordinates: [Number],
            address: String,
            description: String
        },
        location:[
            {
                type:{
                    type: String,
                    default: 'Point',
                    enum: ['Number']
                },
                coordinates: [Number],
                address: String,
                description: String,
                day: Number
            }
        ],
        guides: [
            {
                type: mongoose.Schema.ObjectId,
                ref: 'User' 
            }
        ]
    },
    {
    toJSON: {virtuals: true},
    toObject: {virtuals: true}
    }
    );
tourSchema.virtual('durationWeeks').get(function(){
    return this.duration/ 7 ;
});

tourSchema.virtual('reviews',{
    ref:'Review',
    foreignField:'tour',
    localField: '_id'
});

tourSchema.pre('save',function(){
    this.slug = slugify(this.name,{lower : true})
    next();
});    

// tourSchema.pre('save',async function(next)
// {
//     const guidesPromises = this.guides.map(async id => await User.findById(id));
//    this.guides =  await Promise.all(guidesPromises);
//     next();
// });

// tourSchema.pre('save',function(next){
//     console.log('wil save the document');
//     next();
// });

// tourSchema.post('save',function(doc,next){
//     console.log(doc);
//     next();
// });
// Query middleware
tourSchema.pre(/^find/,function(next){
    this.find({secretTour:{$ne: true}});
    this.start = Date.now();
    next();
});

tourSchema.post(/^find/,function(doc, next){
    console.log(`query took ${Date.now() - this.start} millisecond!`);
    console.log(doc);
    next();
});

tourSchema.pre(/^find/, function(next)
{
    this.populate({
        path: 'guides',
         select: '-__v -passwordChangedAt' 
    });
    next();
})
//Ageration 

tourSchema.pre('aggregate',function(next){
    this.pipeline().unshift({$match:{ secretTour: {$ne:true}}});
    console.log(this.pipeline());
    next();
});

const Tour = mongoose.model('Tour',tourSchema);

module.exports = Tour;