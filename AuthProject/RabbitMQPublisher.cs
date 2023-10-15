namespace AuthorizationServer
{
    using RabbitMQ.Client;
    using System.Text;

    public class RabbitMQPublisher
    {
        private readonly ConnectionFactory _factory;
        private readonly IConnection _connection;
        private readonly IModel _channel;
        private readonly string _exchangeName;

        public RabbitMQPublisher(string hostName, string exchangeName)
        {
            _factory = new ConnectionFactory() { HostName = hostName };
            _connection = _factory.CreateConnection();
            _channel = _connection.CreateModel();
            _exchangeName = exchangeName;

            _channel.ExchangeDeclare(exchange: _exchangeName, type: ExchangeType.Direct);
        }

        public void Publish(string message, string routingKey)
        {
            // Convert the message to bytes.
            var body = Encoding.UTF8.GetBytes(message);

            // Publish the message to the exchange with the specified routing key.
            _channel.BasicPublish(exchange: _exchangeName, routingKey: routingKey, basicProperties: null, body: body);
        }

        public void Dispose()
        {
            _channel.Dispose();
            _connection.Dispose();
        }
    }

}
