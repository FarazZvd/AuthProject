using System;
using System.Text;
using Microsoft.AspNet.Identity;
using Microsoft.AspNetCore.Identity;
//using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using MonitoringService;
using Newtonsoft.Json;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;





internal class Program
{
    private static void Main(string[] args)
    {
        // RabbitMQ client
        var factory = new ConnectionFactory()
        {
            HostName = "localhost",
            Port = 5672,
            UserName = "guest",
            Password = "guest"
        };

        using var connection = factory.CreateConnection();
        using var channel = connection.CreateModel();

        channel.QueueDeclare(queue: "user_signup_queue", durable: false, exclusive: false, autoDelete: false, arguments: null);

        var consumer = new EventingBasicConsumer(channel);
        consumer.Received += (model, ea) =>
        {
            var body = ea.Body;
            var userInfoJson = Encoding.UTF8.GetString(body.ToArray());
            var userInfo = JsonConvert.DeserializeObject<ApplicationUser>(userInfoJson) ?? throw new Exception("Failed to serialize credentials!");

            // Log user's sign-up
            Console.WriteLine($"{userInfo.Email} just registered.");

            // Register a new user
            var user = new ApplicationUser(email: userInfo.Email, password: userInfo.Password);

            InMemoryUserStore.AddUser(user);

            //// Authenticate a user TODO
        };

        channel.BasicConsume(queue: "user_signup_queue", autoAck: true, consumer: consumer);

        Console.WriteLine("Listening for sign-ups. Press [Enter] to exit.");
        Console.ReadLine();
    }
}