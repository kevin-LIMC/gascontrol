-- ======================================================================
-- FASE 1: GESTIÓN DE VEHÍCULOS, RENDIMIENTO Y CONTROL DE FLOTILLAS
-- GasControl - Azure SQL Database
-- ======================================================================

-- 1. Crear tabla de vehículos si no existe
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'vehiculo' AND schema_id = SCHEMA_ID('dbo'))
BEGIN
  CREATE TABLE dbo.vehiculo (
    id_vehiculo INT IDENTITY(1,1) NOT NULL,
    id_cliente INT NULL,
    placas VARCHAR(15) NOT NULL,
    marca_modelo VARCHAR(80) NOT NULL,
    capacidad_tanque DECIMAL(6,2) NOT NULL DEFAULT 50.00,
    odometro_actual INT NOT NULL DEFAULT 0,
    activo BIT NOT NULL DEFAULT 1,
    fecha_alta DATETIME2(0) NOT NULL DEFAULT CAST(SYSDATETIMEOFFSET() AT TIME ZONE 'Central Standard Time (Mexico)' AS DATETIME2(0)),
    CONSTRAINT pk_vehiculo PRIMARY KEY (id_vehiculo),
    CONSTRAINT uq_vehiculo_placas UNIQUE (placas),
    CONSTRAINT fk_vehiculo_cliente FOREIGN KEY (id_cliente) REFERENCES dbo.cliente(id_cliente),
    CONSTRAINT ck_vehiculo_capacidad CHECK (capacidad_tanque > 0),
    CONSTRAINT ck_vehiculo_odometro CHECK (odometro_actual >= 0)
  );
END;

-- 2. Agregar columnas para control de odómetro y tanque en dbo.venta si no existen
IF NOT EXISTS (SELECT * FROM sys.columns WHERE name = 'id_vehiculo' AND object_id = OBJECT_ID('dbo.venta'))
BEGIN
  ALTER TABLE dbo.venta ADD id_vehiculo INT NULL CONSTRAINT fk_venta_vehiculo FOREIGN KEY REFERENCES dbo.vehiculo(id_vehiculo);
END;

IF NOT EXISTS (SELECT * FROM sys.columns WHERE name = 'odometro' AND object_id = OBJECT_ID('dbo.venta'))
BEGIN
  ALTER TABLE dbo.venta ADD odometro INT NULL;
END;

IF NOT EXISTS (SELECT * FROM sys.columns WHERE name = 'tanque_lleno' AND object_id = OBJECT_ID('dbo.venta'))
BEGIN
  ALTER TABLE dbo.venta ADD tanque_lleno BIT NOT NULL DEFAULT 1;
END;
