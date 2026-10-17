import * as THREE from "three";

interface NetworkEdgeProps {
  start: [number, number, number];
  end: [number, number, number];
}

export function NetworkEdge({ start, end }: NetworkEdgeProps) {
  const startVector = new THREE.Vector3(...start);
  const endVector = new THREE.Vector3(...end);

  const direction = new THREE.Vector3()
    .subVectors(endVector, startVector);

  const length = direction.length();

  const midpoint = new THREE.Vector3()
    .addVectors(startVector, endVector)
    .multiplyScalar(0.5);

  const quaternion = new THREE.Quaternion();

  quaternion.setFromUnitVectors(
    new THREE.Vector3(0, 1, 0),
    direction.normalize()
  );

  return (
    <mesh
      position={midpoint}
      quaternion={quaternion}
    >
<cylinderGeometry args={[0.011, 0.011, length, 8]} />

<meshBasicMaterial
  color="#17627f"
  transparent
  opacity={0.58}
/>
    </mesh>
  );
}
