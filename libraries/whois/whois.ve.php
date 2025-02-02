<?php
namespace packages\whois;
class ve_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Titular:',
            'domain.name' => 'Nombre de Dominio:',
            'admin' => 'Contacto Administrativo',
            'tech' => 'Contacto Tecnico',
            'billing' => 'Contacto de Cobranza:',
            'domain.created' => 'Fecha de Creacion:',
            'domain.changed' => 'Ultima Actualizacion:',
            'domain.expires' => 'Fecha de Vencimiento:',
            'domain.status' => 'Estatus del dominio:',
            'domain.nserver' => 'Servidor(es) de Nombres de Dominio'
        );

        $r = array();
        $r['regrinfo'] = get_blocks($data_str['rawdata'], $items);

        if (!isset($r['regrinfo']['domain']['created']) || is_array($r['regrinfo']['domain']['created'])) {
            $r['regrinfo'] = array('registered' => 'no');
            return $r;
        }

        $dns = array();

        foreach ($r['regrinfo']['domain']['nserver'] as $nserv) {
            if ($nserv[0] == '-')
                $dns[] = $nserv;
        }

        $r['regrinfo']['domain']['nserver'] = $dns;
        $r['regrinfo'] = get_contacts($r['regrinfo']);
        $r['regyinfo'] = array(
            'referrer' => 'http://registro.nic.ve',
            'registrar' => 'NIC-Venezuela - CNTI'
        );
        return $r;
    }

}
