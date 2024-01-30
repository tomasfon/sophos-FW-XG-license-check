#!/usr/bin/perl

# Autor: Tomás Fonseca - NSoluciones
# Sitio web: https://www.nsoluciones.com/
# Fecha: Enero 2024
# Versión: 2.0
# perl program to check expiration of a sophos license, for centreon


use Net::SNMP;
use Getopt::Long;
use DateTime;

# Variables por defecto
my $device_ip = '127.0.0.1';  # Cambia la IP por defecto a la deseada
my $community = 'public';    # Cambia la comunidad por defecto a la deseada

# Opciones de línea de comandos
GetOptions(
    'ip=s'       => \$device_ip,
    'community=s' => \$community,
);

# OID para la Network Protection Registration License
my $network_expiration_date_oid = '.1.3.6.1.4.1.2604.5.1.5.2.2.0';

# Crear la sesión SNMP
my ($session, $error) = Net::SNMP->session(
    -hostname  => $device_ip,
    -community => $community,
);

# Manejar errores en la creación de la sesión
die "Error al crear la sesión SNMP: $error" unless $session;

# Consultar el estado de la licencia
my $network_expiration_date_response = $session->get_request(-varbindlist => [$network_expiration_date_oid]);

# Manejar errores en la consulta
die "Error en la consulta SNMP: " . $session->error() unless defined $network_expiration_date_response;

# Obtener la fecha de expiración de Network Protection Registration License
my $network_expiration_date = $network_expiration_date_response->{$network_expiration_date_oid};

# Verificar que la fecha se haya obtenido correctamente
unless ($network_expiration_date) {
    die "Error: No se pudo obtener la fecha de expiración de la licencia.\n";
}

# Formato de fecha devuelto por Sophos XG Firewall: Mar 23 2025
# Parsear la fecha con una expresión regular
my ($month, $day, $year) = $network_expiration_date =~ /^(\w{3}) (\d{1,2}) (\d{4})$/;

# Verificar que la fecha se haya parseado correctamente
unless ($month && $day && $year) {
    die "Error: No se pudo parsear la fecha de expiración.\n";
}

# Mapear nombres de meses a números
my %month_map = (
    Jan => 1, Feb => 2, Mar => 3, Apr => 4, May => 5, Jun => 6,
    Jul => 7, Aug => 8, Sep => 9, Oct => 10, Nov => 11, Dec => 12,
);

# Crear un objeto DateTime
my $expiration_date_dt = DateTime->new(
    year      => $year,
    month     => $month_map{$month},
    day       => $day,
    hour      => 23,
    minute    => 59,
    second    => 59,
    time_zone => 'local',
);

# Verificar que la creación del objeto DateTime haya sido exitosa
unless ($expiration_date_dt) {
    die "Error: No se pudo crear el objeto DateTime para la fecha de expiración.\n";
}

# Obtener la fecha actual
my $current_date_dt = DateTime->now;

# Calcular la diferencia en días
my $days_remaining = $expiration_date_dt->delta_days($current_date_dt)->delta_days;

# Imprimir resultados
print "Network Protection Registration License:\n";
print "  Fecha de expiración: $network_expiration_date\n";

# Verificar el estado de la licencia y mostrar la advertencia o crítico según el umbral
if ($days_remaining < 0) {
    print "  La licencia ha caducado.\n";
    exit 2;  # Estado CRÍTICO
} elsif ($days_remaining <= 15) {
    print "  ¡CRÍTICO! La licencia caduca en $days_remaining días.\n";
    exit 2;  # Estado CRÍTICO
} elsif ($days_remaining <= 30) {
    print "  ¡ADVERTENCIA! La licencia caduca en $days_remaining días.\n";
    exit 1;  # Estado ADVERTENCIA
} else {
    print "  La licencia está vigente.\n";
    exit 0;  # Estado OK
}


# Cerrar la sesión SNMP
$session->close();
