import { Injectable, BadRequestException } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { User } from "../database/entities/user.entity";
import * as bcrypt from "bcrypt";
import { JwtService } from "@nestjs/jwt";

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private jwtService: JwtService
  ) {}

  async register(
    username: string,
    email: string,
    password: string
  ): Promise<User> {
    try {
      if (!password || password.trim().length === 0) {
        throw new BadRequestException("Password cannot be empty");
      }
      if (!username || username.trim().length === 0) {
        throw new BadRequestException("Username cannot be empty");
      }
      if (!email || email.trim().length === 0) {
        throw new BadRequestException("Email cannot be empty");
      }
      if (!email.includes("@")) {
        throw new BadRequestException("Invalid email");
      }
      const existingUser = await this.userRepository.findOne({
        where: { email },
      });
      if (existingUser) {
        throw new BadRequestException("Email is already taken");
      }

      if (password.length < 8) {
        throw new BadRequestException("Password must be at least 8 characters");
      }

      const salt = await bcrypt.genSalt();
      if (!salt) {
        throw new BadRequestException("Failed to generate salt");
      }

      const hashedPassword = await bcrypt.hash(password, salt);
      if (!hashedPassword) {
        throw new BadRequestException("Failed to generate hash password");
      }

      const newUser = this.userRepository.create({
        username,
        email,
        password: hashedPassword,
        salt,
      });

      return this.userRepository.save(newUser);
    } catch (error) {
      throw error;
    }
  }

  async findUser(): Promise<User[]> {
    return await this.userRepository.find();
  }

  async findUserById(id: number): Promise<User> {
    return this.userRepository.findOne({ where: { id } });
  }

  async validateOldPassword(id: number, oldPassword: string): Promise<boolean> {
    const user = await this.findUserById(id);
    if (user && (await bcrypt.compare(oldPassword, user.password))) {
      return true;
    }
    return false;
  }

  async updateUser(
    id: number,
    username: string,
    oldPassword: string,
    password: string
  ): Promise<User> {
    if (!id) {
      throw new Error("Invalid ID");
    }

    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new Error("User not found");
    }

    if (username) {
      user.username = username;
    }

    if (password) {
      if (password.length < 8) {
        throw new Error("Password must be at least 8 characters long");
      }
      if (!oldPassword) {
        throw new Error("Old password is required");
      }

      const validPassword = await this.validateOldPassword(id, oldPassword);
      if (!validPassword) {
        throw new Error("Invalid old password");
      }

      const salt = await bcrypt.genSalt();
      const hashedPassword = await bcrypt.hash(password, salt);
      user.password = hashedPassword;
      user.salt = salt;
    }

    await this.userRepository.save(user);

    const { password: _, salt: __, ...updatedUser } = user;
    return user;
  }

  async login(user: User): Promise<{ access_token: string }> {
    const payload = { email: user.email, sub: user.id };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.userRepository.findOne({ where: { email } });
    if (user && (await bcrypt.compare(password, user.password))) {
      return user;
    }
    return null;
  }
}
