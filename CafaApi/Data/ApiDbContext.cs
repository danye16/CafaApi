﻿using CafaApi.Modelo;
using Microsoft.EntityFrameworkCore;

namespace CafaApi.Data
{
    public class ApiDbContext : DbContext
    {
        public ApiDbContext(DbContextOptions<ApiDbContext> options) : base(options) { }
        public DbSet<User> Users { get; set; }
    }
}
