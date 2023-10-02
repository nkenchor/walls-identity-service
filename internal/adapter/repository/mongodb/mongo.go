package repository

import (
	"context"
	"fmt"
	"strconv"
	configuration "walls-identity-service/internal/core/helper/configuration-helper"
	errorhelper "walls-identity-service/internal/core/helper/error-helper"
	logger "walls-identity-service/internal/core/helper/log-helper"
	ports "walls-identity-service/internal/port"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoRepositories struct {
	Identity ports.IdentityRepository
}

func ConnectToMongo() (MongoRepositories, error) {
	logger.LogEvent("INFO", "Establishing mongoDB connection with given credentials...")
	//var mongoCredentials, authSource string
	// if dbIdentityname != "" && dbPassword != "" {
	// 	mongoCredentials = fmt.Sprint(dbIdentityname, ":", dbPassword, "@")
	// 	authSource = fmt.Sprint("authSource=", authdb, "&")
	// }
	mongoUrl := fmt.Sprint(configuration.ServiceConfiguration.DBConnectionString)
	clientOptions := options.Client().ApplyURI(mongoUrl) // Connect to
	logger.LogEvent("INFO", "Connecting to MongoDB...")
	db, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		//log.Println(err)
		//log.Fatal(err)
		logger.LogEvent("ERROR", errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return MongoRepositories{}, err
	}

	// Check the connection
	logger.LogEvent("INFO", "Confirming MongoDB Connection...")
	err = db.Ping(context.TODO(), nil)
	if err != nil {
		//log.Println(err)
		//log.Fatal(err)
		logger.LogEvent("ERROR", errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return MongoRepositories{}, err
	}

	//helper.LogEvent("Info", "Connected to MongoDB!")
	logger.LogEvent("INFO", "Establishing Database collections and indexes...")
	conn := db.Database(configuration.ServiceConfiguration.DBName)

	identityCollection := conn.Collection("identity")

	repo := MongoRepositories{
		Identity: NewIdentity(identityCollection),
	}

	return repo, nil
}

// CreateIndex - creates an index for a specific field in a collection
//func CreateIndex(collection *mongo.Collection, field string, unique bool) bool {
//
//	mod := mongo.IndexModel{
//		Keys:    bson.M{field: 1}, // index in ascending order or -1 for descending order
//		Options: options.Index().SetUnique(unique),
//	}
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//
//	_, err := collection.Indexes().CreateOne(ctx, mod)
//	if err != nil {
//		helper.LogEvent("ERROR", err.Error())
//		fmt.Println(err.Error())
//
//		return false
//	}
//	return true
//}

func GetPage(page string) (*options.FindOptions, error) {
	if page == "all" {
		return nil, nil
	}
	var limit, e = strconv.ParseInt(configuration.ServiceConfiguration.PageLimit, 10, 64)
	var pageSize, ee = strconv.ParseInt(page, 10, 64)
	if e != nil || ee != nil {
		return nil, errorhelper.ErrorMessage(errorhelper.NoRecordError, "Error in page-size or limit-size.")
	}
	findOptions := options.Find().SetLimit(limit).SetSkip(limit * (pageSize - 1))
	return findOptions, nil
}
