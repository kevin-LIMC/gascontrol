# GasControl Web

Página web + API (Node.js/Express) para tu base de datos **GasControl** en **Azure SQL Database**.

## Puesta en marcha

1. **Base de datos**: ejecuta tu script T-SQL completo en la base `gascontrol` de Azure (verifica que el archivo no esté cortado: el `INSERT` de ventas debe terminar con `;`).
2. **Firewall de Azure**: en el portal, tu servidor SQL → *Redes* → agrega tu IP pública (y "Permitir servicios de Azure" si lo subes a App Service).
3. En esta carpeta:
   ```
   npm install
   copy .env.example .env      (Linux/Mac: cp .env.example .env)
   ```
   Edita `.env` con servidor, base, usuario, contraseña y un `JWT_SECRET` largo.
4. **Contraseñas**: el script trae `hash_demo_*`, que no sirven para iniciar sesión.
   ```
   npm run set-passwords
   ```
   Pone la contraseña `GasControl2026!` a los 6 usuarios de ejemplo (o pásala tú: `npm run set-passwords -- "OtraClave123"`).
5. `npm start` y abre http://localhost:3000

Usuarios de ejemplo: `admin`, `supervisor1`, `despachador1`, `despachador2`, `gerente1`, `contador1`.

## Qué puede hacer cada rol

| Rol | Acceso |
|---|---|
| Despachador | Registrar ventas en sus turnos abiertos y consultarlas |
| Supervisor | Abrir/cerrar turnos (corte de caja), cancelar ventas, cargas de combustible, inventario, reportes |
| Gerencia | Panel, inventario, reportes, cortes, facturas (consulta) y bitácora |
| Contabilidad | Facturación, clientes, reportes |
| Administrador | Todo lo anterior + usuarios, precios y bitácora |

## Cómo usa tu base de datos

- Las **reglas de negocio siguen en SQL**: turno abierto, bomba activa, existencia, descuento/regreso de litros en tanques (triggers) y el cierre de turno (`sp_cerrar_turno`). Los mensajes de esas reglas se muestran tal cual en la página.
- Los reportes leen tus vistas `vw_*`.
- Cada operación importante escribe en `bitacora_auditoria` (que tu BD protege contra cambios y borrados).
- Las ventas nunca se borran: se cancelan (como exige tu esquema).
- Las fechas se guardan en hora de Ciudad de México (Azure trabaja en UTC por defecto).

## Cosas a tener en cuenta

- El **folio fiscal** de las facturas es un UUID de ejemplo; no timbra CFDI.
- `factura.id_venta` es único: una venta con factura cancelada no puede volver a facturarse.
- El total teórico del corte (`sp_cerrar_turno`) suma **todas** las ventas, no solo efectivo; la caja real debe capturarse con ese criterio.
- Una venta de un turno ya cerrado no se puede cancelar (para no alterar el corte).
- Para producción: usa HTTPS (por ejemplo, Azure App Service), una `JWT_SECRET` fuerte y un usuario SQL con permisos solo sobre esta base. Los tokens duran 8 horas.
