import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';

import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JWTPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(
    private readonly jwtService: JwtService,
  ) {
    super();
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB Connected');
  }

  async signJWT( payload: JWTPayload ) {
    return this.jwtService.sign(payload);
  }

  async verifyToken(token: string) {
    try {
      const {sub, iat, exp, ...user} = this.jwtService.verify(token, {
        secret: envs.jwt_secret
      });

      return {
        user,
        token: await this.signJWT(user)
      }

    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message
      })
    }
  }
  
  async registerUser(registerUserDto: RegisterUserDto) {
    const { email, name, password } = registerUserDto;
    try {

      const user = await this.user.findUnique({
        where: {email}
      });

      if ( user ) {
        throw new RpcException({
          status: 400,
          message: 'User already exists'
        })
      }

      const newUser = await this.user.create({
        data: {
          email,
          password: bcrypt.hashSync(password, 10),
          name
        }
      })

      const { password: __, ...rest } = newUser;

      return {
        user: rest,
        token: await this.signJWT(rest),
      }

    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message
      })
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {

    const { email, password } = loginUserDto;

    try {
      
      const user = await this.user.findUnique({
        where: { email }
      });

      if ( !user ) {
        throw new RpcException({
          status: 400,
          message: 'User/Password not valid'
        })
      }

      if ( !bcrypt.compareSync(password, user.password) ) {
        throw new RpcException({
          status: 400,
          message: 'User/Password not valid'
        })
      }

      const { password: __, ...rest } = user;

      return {
        user: rest,
        token: await this.signJWT(rest),
      }

    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message
      })
    }
  }
}
