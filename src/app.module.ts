import { Module } from "@nestjs/common";
import { AppController } from "./app.controller";
import { AppService } from "./app.service";
import { DatabaseModule } from "./database/database.module";
import { UserModule } from "./user/user.module";
import { TypeOrmModule } from "@nestjs/typeorm";
import { ConfigModule } from "@nestjs/config";

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: "postgres",
      host: "localhost",
      port: 5432,
      username: "new_user", // replace with your PostgreSQL username
      password: "", // replace with your PostgreSQL password
      database: "new_db", // replace with your PostgreSQL database name
      entities: [__dirname + "/**/*.entity{.ts,.js}"],
      synchronize: true, // set to false in production for safety
    }),
    DatabaseModule,
    UserModule,
    ConfigModule.forRoot({
      isGlobal: true,
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
