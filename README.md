
# Flask_JWT

Simple Flask API using JWT and PostgreSQL
## Deployment

To deploy this project run

```bash
  pip install -r requirements.txt
```


## API Reference

#### Get Bearer

```bash
  GET /login
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `username` | `string` | **Required**. Username of an account in the database |
| `password` | `string` | **Required**. Password linked to the account below |

#### Check Bearer

```bash
  GET /check_token
```

| Header | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `x-access-token`      | `string` | **Required**. JWT Token returned during the connection |


## Contributing

Contributions are always welcome!


## Feedback

If you have any feedback, please reach out to us at XXXXXX (no)

