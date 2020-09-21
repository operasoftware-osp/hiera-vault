Puppet::Functions.create_function(:hiera_vault) do

  begin
    require 'json'
  rescue LoadError => e
    raise Puppet::DataBinding::LookupError, "[hiera-vault] Must install json gem to use hiera-vault backend"
  end
  begin
    require 'vault'
  rescue LoadError => e
    raise Puppet::DataBinding::LookupError, "[hiera-vault] Must install vault gem to use hiera-vault backend"
  end
  begin
    require 'debouncer'
  rescue LoadError => e
    raise Puppet::DataBinding::LookupError, "[hiera-vault] Must install debouncer gem to use hiera-vault backend"
  end


  dispatch :lookup_key do
    param 'Variant[String, Numeric]', :key
    param 'Hash', :options
    param 'Puppet::LookupContext', :context
  end

  @@vault    = Vault::Client.new
  @@shutdown = Debouncer.new(10) { @@vault.shutdown() }

  def lookup_key(key, options, context)
    if confine_keys = options['confine_to_keys']
      raise ArgumentError, '[hiera-vault] confine_to_keys must be an array' unless confine_keys.is_a?(Array)

      begin
        confine_keys = confine_keys.map { |r| Regexp.new(r) }
      rescue StandardError => e
        raise Puppet::DataBinding::LookupError, "[hiera-vault] creating regexp failed with: #{e}"
      end

      regex_key_match = Regexp.union(confine_keys)

      unless key[regex_key_match] == key
        context.explain { "[hiera-vault] Skipping hiera_vault backend because key does not match confine_to_keys" }
        context.not_found
      end
    end

    value = vault_get(key, options, context)
    if value == nil
      context.not_found
    end
    return value
  end

  def normalize_key(key)
    # vault_storage::a::b::c::d -> a::b::c::d
    key = key.split("::")[1..key.length()].join("::");
    # a::b::c::d -> [a, b, c, d]
    key = key.split('::')

    # [a, b, c, d] -> [a, b/c, :d]
    return [key[0], key[1..-2].join('/'), key[-1].to_sym]
  end

  def vault_get(key, options, context)
    # vault_storage::common::some::strange::path::some_key => [common, some/strange/path, :some_key]
    scope, value_path, value_key = normalize_key(key)

    begin
      @@vault.configure do |config|
        config.address = options['address'] unless options['address'].nil?
        config.token = options['token'] unless options['token'].nil?
        config.ssl_pem_file = options['ssl_pem_file'] unless options['ssl_pem_file'].nil?
        config.ssl_verify = options['ssl_verify'] unless options['ssl_verify'].nil?
        config.ssl_ca_cert = options['ssl_ca_cert'] if config.respond_to? :ssl_ca_cert
        config.ssl_ca_path = options['ssl_ca_path'] if config.respond_to? :ssl_ca_path
        config.ssl_ciphers = options['ssl_ciphers'] if config.respond_to? :ssl_ciphers
      end

      if @@vault.sys.seal_status.sealed?
        raise Puppet::DataBinding::LookupError, "[hiera-vault] vault is sealed"
      end

      context.explain { "[hiera-vault] Client configured to connect to #{@@vault.address}" }
    rescue StandardError => e
      @@shutdown.call
      @@vault = nil
      raise Puppet::DataBinding::LookupError, "[hiera-vault] Skipping backend. Configuration error: #{e}"
    end

    answer = nil

    # Only kv2 mounts supported so far
    allowed_mounts = interpolate(context, options['mounts']['kv2'])
    allowed_mounts.each do |mount|
      mount = rstrip(mount, '/')
      context.explain { "[hiera-vault] Looking for scope #{scope} under #{mount}" }
      unless mount.end_with?("/#{scope}")
        next
      end
      path = rstrip(File.join(mount, value_path), '/')
      context.explain { "[hiera-vault] Looking in path #{path}" }

      begin
        secret = @@vault.logical.read(path)
      rescue Vault::HTTPConnectionError
        context.explain { "[hiera-vault] Could not connect to read secret: #{path}" }
      rescue Vault::HTTPError => e
        context.explain { "[hiera-vault] Could not read secret #{path}: #{e.errors.join("\n").rstrip}" }
      end

      next if secret.nil?

      context.explain { "[hiera-vault] Read secret: #{value_path} #{value_key}" }

      # in case of KV v2 secret.data contains dict with :data key inside
      data = secret.data[:data] || {}

      if data.has_key?(value_key)
        answer = data[value_key]
        break
      end
    end

    return answer
  end

  private

  def interpolate(context, mounts)
    allowed_mounts = []
    mounts.each do |mount|
      mount = context.interpolate(mount)
      # secret/puppet/scope1,scope2 => [[secret], [puppet], [scope1, scope2]]
      segments = mount.split('/').map { |segment| segment.split(',') }
      allowed_mounts += build_mounts(segments, [""])
    end
    return allowed_mounts
  end

  def build_mounts(segments, current_paths)
    if segments.empty?
      return current_paths
    end
    segment = segments.shift()
    new_paths = []
    current_paths.each do |path|
      segment.each do |s|
        new_paths.push(path + '/' + s)
      end
    end
    @@shutdown.call
    return build_mounts(segments, new_paths)
  end

  def rstrip(v, c)
    if v.end_with?(c)
      return v[0..-2]
    end
    return v
  end

end
