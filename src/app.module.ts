import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import configuration from './config/configuration';

import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { MailerModule } from '@nestjs-modules/mailer'
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import { join } from 'path';

@Module({
    imports: [
        ConfigModule.forRoot({
            isGlobal: true,
            load: [configuration],
        }),

        TypeOrmModule.forRootAsync({
            imports: [ConfigModule],
            useFactory: (configService: ConfigService) => ({
                type: 'postgres',
                host: configService.get('database.host'),
                port: configService.get('database.port'),
                username: configService.get('database.username'),
                password: configService.get('database.password'),
                database: configService.get('database.name'),
                entities: [__dirname + '/**/*.entity{.ts,.js}'],
                synchronize: configService.get('nodeEnv') === 'development',
                logging: configService.get('nodeEnv') === 'development',
            }),
            inject: [ConfigService],
        }),

        TypeOrmModule.forRootAsync({
            imports: [ConfigModule],
            useFactory: (configService: ConfigService) => ({
                ttl: configService.get('throttle.ttl'),
                limit: configService.get('throttle.limit'),
            }),
            inject: [ConfigService],
        }),

        MailerModule.forRootAsync({
            imports: [ConfigModule],
            useFactory: (configService: ConfigService) => ({
                transport: {
                    host: configService.get('email.host'),
                    port: configService.get('email.port'),
                    auth: {
                        user: configService.get('email.user'),
                        pass: configService.get('email.pass'),
                    },
                },
                defaults: {
                    from: `No Reply <${configService.get('email.from')}>`,
                },
                template: {
                    dir: join(__dirname, 'mail/email'),
                    adapter: new HandlebarsAdapter(),
                    options: {
                        strict: true
                    },
                },
            }),
            inject: [ConfigService],
        }),

    ],
    controllers: [AppController],
    providers: [AppService],
})
export class AppModule { }
