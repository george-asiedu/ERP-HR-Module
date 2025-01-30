export const UserResponseExample = {
  message: 'Success',
  data: {
    id: 1,
    name: 'George Asiedu',
    email: 'george.asiedu@gmail.com',
    role: 'admin',
  }
}

export const LoginResponseExample = {
  message: 'Success',
  data: {
    accessToken: 'accessToken',
    refreshToken: 'refreshToken',
  }
}

export const GetAllUsersResponseExample = {
  message: 'Success',
  data: [
    {
      id: 1,
      name: 'George Asiedu',
      email: 'george.asiedu@gmail.com',
      role: 'admin',
    }
  ]
}

export const BadRequestExample = [
  'name should not be empty',
  'email must be an email',
  'password must be at least 8 characters long'
]

export const LoginBadRequestExample = [
  'email must be an email',
  'password must be at least 8 characters long'
]