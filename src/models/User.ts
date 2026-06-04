import { DataTypes, Model } from 'sequelize';
import sequelize from '../config/database';
import bcrypt from 'bcryptjs';

export enum UserRole {
  ADMIN = 'admin',
  DIRECTOR = 'director',
  WAREHOUSE_KEEPER = 'warehouse_keeper',
  SELLER = 'seller',
  SPARE_PARTS = 'spare_parts'
}

interface UserAttributes {
  id?: string;
  email: string;
  phone: string;
  password: string;
  fullName: string;
  role: UserRole;
  isActive: boolean;
  createdAt?: Date;
  updatedAt?: Date;
}

class User extends Model<UserAttributes> implements UserAttributes {
  public id!: string;
  public email!: string;
  public phone!: string;
  public password!: string;
  public fullName!: string;
  public role!: UserRole;
  public isActive!: boolean;
  public createdAt!: Date;
  public updatedAt!: Date;

  async comparePassword(enteredPassword: string): Promise<boolean> {
    return await bcrypt.compare(enteredPassword, this.password);
  }
}

User.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        isEmail: true,
      },
    },
    phone: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    fullName: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    role: {
      type: DataTypes.ENUM(
        UserRole.ADMIN,
        UserRole.DIRECTOR,
        UserRole.WAREHOUSE_KEEPER,
        UserRole.SELLER,
        UserRole.SPARE_PARTS
      ),
      defaultValue: UserRole.SELLER,
    },
    isActive: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
    },
  },
  {
    sequelize,
    tableName: 'users',
    timestamps: true,
    hooks: {
      beforeCreate: async (user: User) => {
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(user.password, salt);
      },
      beforeUpdate: async (user: User) => {
        if (user.changed('password')) {
          const salt = await bcrypt.genSalt(10);
          user.password = await bcrypt.hash(user.password, salt);
        }
      },
    },
  }
);

export default User;
