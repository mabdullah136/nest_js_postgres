import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Query,
  HttpCode,
  BadRequestException,
  NotFoundException,
  UseInterceptors,
  UnauthorizedException,
} from "@nestjs/common";
import { UserService } from "./user.service";
import { User } from "../database/entities/user.entity";
import { FileInterceptor } from "@nestjs/platform-express";
import * as bcrypt from "bcrypt";

@Controller("auth")
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post("register")
  @UseInterceptors(FileInterceptor("file"))
  @HttpCode(201)
  async register(
    @Body() body: { username: string; email: string; password: string }
  ) {
    if (!body.password || body.password.trim().length === 0) {
      throw new BadRequestException("Password cannot be empty");
    }
    if (!body.username || body.username.trim().length === 0) {
      throw new BadRequestException("Username cannot be empty");
    }
    if (!body.email || body.email.trim().length === 0) {
      throw new BadRequestException("Email cannot be empty");
    }
    if (!body.email.includes("@")) {
      throw new BadRequestException("Invalid email");
    }
    if (body.password.length < 8) {
      throw new BadRequestException("Password must be at least 8 characters");
    }
    const user = await this.userService.register(
      body.username,
      body.email,
      body.password
    );
    return {
      status: "success",
      message: "User registered successfully",
      data: user,
    };
  }

  @Get("list")
  @HttpCode(200)
  async profile(@Body() body: { token: string }) {
    const user = await this.userService.findUser();
    return {
      status: "success",
      message: "User list",
      data: user,
    };
  }

  @Get("profile")
  @UseInterceptors(FileInterceptor("file"))
  @HttpCode(200)
  async profile1(@Query("id") id: string) {
    try {
      const user = await this.userService.findUserById(parseInt(id));
      if (!user) {
        throw new NotFoundException("User not found");
      }
      return {
        status: "success",
        message: "User profile",
        data: user,
      };
    } catch (error) {
      throw new BadRequestException("Invalid user ID");
    }
  }

  async validateOldPassword(id: number, oldPassword: string): Promise<boolean> {
    const user = await this.userService.findUserById(id);
    if (user && (await bcrypt.compare(oldPassword, user.password))) {
      return true;
    }
    return false;
  }

  @Post("update")
  @UseInterceptors(FileInterceptor("file"))
  @HttpCode(200)
  async update(
    @Body()
    body: {
      id: number;
      username: string;
      oldPassword: string;
      password: string;
    }
  ) {
    const userId = body.id;
    if (!userId) {
      throw new BadRequestException("Id not found");
    }

    const user = await this.userService.updateUser(
      body.id,
      body.username,
      body.oldPassword,
      body.password
    );

    return {
      status: "success",
      message: "User updated successfully",
      data: user,
    };
  }

  @Post("login")
  @UseInterceptors(FileInterceptor("file"))
  @HttpCode(200)
  async login(@Body() body: { email: string; password: string }) {
    const user = await this.userService.validateUser(body.email, body.password);
    if (!user) {
      throw new UnauthorizedException("Invalid credentials");
    }
    const token = await this.userService.login(user);
    return {
      status: "success",
      message: "User logged in Successfully",
      data: token,
    };
  }
}
