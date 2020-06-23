var Indico = {{ indico_vars | tojson }};

{{ template_hook('vars-js') }}

Indico.Urls.Base = 'http://' + location.host;
