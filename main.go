package main

import (
	"context"
	"log"
	"net"
	"strateegy/jwt-strateegy/pb"
	"strateegy/jwt-strateegy/utils"

	"google.golang.org/grpc"
)

type Server struct {
	pb.UnimplementedSendIDServer
	pb.UnimplementedSendTokenServer
	pb.UnimplementedSendValidateServer
}

func (service *Server) RequestToken(ctx context.Context, req *pb.ID) (*pb.Token, error) {
	ID := req.GetID()

	token, err := utils.NewJWTService().GenerateToken(ID)
	if err != nil {
		return nil, err
	}

	response := &pb.Token{
		Token: token,
	}

	return response, nil
}
func (service *Server) mustEmbedUnimplementedSendTokenServer() {}

func (service *Server) RequestID(ctx context.Context, req *pb.Token) (*pb.ID, error) {
	token := req.GetToken()
	token, err := utils.RemoveBearer(token)
	if err != nil {
		return nil, err
	}

	ID, err := utils.NewJWTService().GetIDFromToken(token)
	if err != nil {
		return nil, err
	}

	response := &pb.ID{
		ID: ID,
	}

	return response, nil
}
func (service *Server) mustEmbedUnimplementedSendIDServer() {}

func (service *Server) RequestValidate(ctx context.Context, req *pb.Token) (*pb.Validate, error) {
	token := req.GetToken()
	token, err := utils.RemoveBearer(token)
	if err != nil {
		return nil, err
	}

	isValid := utils.NewJWTService().ValidateToken(token)

	response := &pb.Validate{
		Validate: isValid,
	}

	return response, nil
}
func (service *Server) mustEmbedUnimplementedSendValidateServer() {}

func main() {
	grpcServer := grpc.NewServer()

	pb.RegisterSendTokenServer(grpcServer, &Server{})
	pb.RegisterSendIDServer(grpcServer, &Server{})
	pb.RegisterSendValidateServer(grpcServer, &Server{})

	port := ":3335"

	listener, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Grpc Server running at port: %v", port)

	grpc_Error := grpcServer.Serve(listener)
	if grpc_Error != nil {
		log.Fatal(grpc_Error)
	}
}
