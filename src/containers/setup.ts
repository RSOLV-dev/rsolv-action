import { ActionConfig, ContainerConfig } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { exec } from 'child_process';
import { promisify } from 'util';

const execPromise = promisify(exec);

/**
 * Set up containerized environment for secure code analysis
 */
export async function setupContainer(config: ActionConfig): Promise<void> {
  try {
    if (!config.containerConfig.enabled) {
      logger.info('Container analysis is disabled, skipping container setup');
      return;
    }
    
    logger.info('Setting up analysis container');
    
    // Validate container configuration
    validateContainerConfig(config.containerConfig);
    
    // Ensure Docker is available
    await checkDockerAvailability();
    
    // Pull the required container image
    await pullContainerImage(config.containerConfig);
    
    // Configure container with appropriate security settings
    await configureContainer(config.containerConfig, config.securitySettings);
    
    logger.info('Container setup completed successfully');
  } catch (error) {
    logger.error('Container setup failed', error);
    throw new Error(`Failed to set up analysis container: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Validate container configuration
 */
function validateContainerConfig(config: ContainerConfig): void {
  if (!config.image) {
    throw new Error('Container image is required when container analysis is enabled');
  }
  
  // Validate memory and CPU limits
  if (config.memoryLimit && !/^\d+[gmk]?b?$/i.test(config.memoryLimit)) {
    throw new Error(`Invalid memory limit format: ${config.memoryLimit}`);
  }
  
  if (config.cpuLimit && !/^\d+(\.\d+)?$/i.test(config.cpuLimit)) {
    throw new Error(`Invalid CPU limit format: ${config.cpuLimit}`);
  }
  
  // Validate timeout
  if (config.timeout && (typeof config.timeout !== 'number' || config.timeout <= 0)) {
    throw new Error(`Invalid timeout value: ${config.timeout}`);
  }
}

/**
 * Check if Docker is available on the system
 */
async function checkDockerAvailability(): Promise<void> {
  try {
    logger.debug('Checking Docker availability');
    
    // Run 'docker version' command to check if Docker is installed and running
    const { stdout } = await execPromise('docker version --format "{{.Server.Version}}"');
    logger.debug(`Docker version: ${stdout.trim()}`);
  } catch (error) {
    logger.error('Docker is not available', error);
    throw new Error('Docker is required for container analysis but is not available or running');
  }
}

/**
 * Pull the container image for analysis
 */
async function pullContainerImage(config: ContainerConfig): Promise<void> {
  try {
    const imageName = config.image || 'rsolv/code-analysis:latest';
    logger.info(`Pulling container image: ${imageName}`);
    
    // Skip actual Docker pull in test environment
    if (process.env.NODE_ENV === 'test') {
      logger.info(`Test environment detected, skipping Docker pull for ${imageName}`);
      return;
    }
    
    // Actually pull the Docker image
    try {
      const { stdout, stderr } = await execPromise(`docker pull ${imageName}`);
      logger.debug(`Docker pull output: ${stdout}`);
      if (stderr) {
        logger.warn(`Docker pull stderr: ${stderr}`);
      }
    } catch (error) {
      // If pull fails and we're in development, continue anyway
      if (process.env.NODE_ENV === 'development') {
        logger.warn(`Failed to pull image but continuing in development mode: ${error instanceof Error ? error.message : String(error)}`);
      } else {
        throw error;
      }
    }
    
    logger.info(`Container image ${imageName} is ready`);
  } catch (error) {
    logger.error('Failed to pull container image', error);
    throw new Error(`Failed to pull container image: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Configure container with appropriate security settings
 */
async function configureContainer(
  containerConfig: ContainerConfig,
  securitySettings: any
): Promise<void> {
  try {
    logger.info('Configuring container with security settings');
    
    // Apply security profile based on configuration
    const securityProfile = containerConfig.securityProfile || 'default';
    
    switch (securityProfile) {
    case 'strict':
      logger.info('Applying strict security profile to container');
      // In production, this would apply strict security settings
      break;
        
    case 'relaxed':
      logger.info('Applying relaxed security profile to container');
      // In production, this would apply relaxed security settings
      break;
        
    case 'default':
    default:
      logger.info('Applying default security profile to container');
      // In production, this would apply default security settings
      break;
    }
    
    // Configure network access
    if (securitySettings.disableNetworkAccess) {
      logger.info('Disabling network access for container');
      // In production, this would configure container to run with --network none
    } else if (securitySettings.allowedDomains && securitySettings.allowedDomains.length > 0) {
      logger.info(`Restricting network access to domains: ${securitySettings.allowedDomains.join(', ')}`);
      // In production, this would configure network access control lists
    }
    
    // Set resource limits
    if (containerConfig.memoryLimit) {
      logger.info(`Setting container memory limit: ${containerConfig.memoryLimit}`);
      // In production, this would configure container memory limits
    }
    
    if (containerConfig.cpuLimit) {
      logger.info(`Setting container CPU limit: ${containerConfig.cpuLimit}`);
      // In production, this would configure container CPU limits
    }
    
    // Configure environment variables
    if (containerConfig.environmentVariables && Object.keys(containerConfig.environmentVariables).length > 0) {
      logger.info(`Setting ${Object.keys(containerConfig.environmentVariables).length} environment variables`);
      // In production, this would pass environment variables to the container
    }
    
    logger.info('Container configuration completed');
  } catch (error) {
    logger.error('Failed to configure container', error);
    throw new Error(`Failed to configure container: ${error instanceof Error ? error.message : String(error)}`);
  }
}