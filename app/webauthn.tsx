import { useLocalSearchParams, useRouter } from "expo-router";
import { useEffect, useState } from "react";
import { StyleSheet, Text, View } from "react-native";

export default function WebAuthnCallback() {
  const params = useLocalSearchParams();
  const router = useRouter();
  const [message, setMessage] = useState("Processing WebAuthn result...");

  useEffect(() => {
    try {
      const resultParam = params.result as string;
      if (resultParam) {
        const result = JSON.parse(decodeURIComponent(resultParam));
        console.log("WebAuthn result:", result);

        if (result.result?.verified) {
          setMessage("✓ Authentication successful!");
          // Navigate back to the main screen after a short delay
          setTimeout(() => {
            router.replace("/");
          }, 10000);
        } else if (result.error) {
          setMessage(`✗ Error: ${result.error}`);
        } else {
          setMessage("Result: " + JSON.stringify(result, null, 2));
        }
      } else {
        setMessage("No result parameter found");
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      setMessage(`Error parsing result: ${errorMessage}`);
      console.error("WebAuthn callback error:", error);
    }
  }, [params, router]);

  return (
    <View style={styles.container}>
      <Text style={styles.title}>WebAuthn Callback</Text>
      <Text style={styles.message}>{message}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
    padding: 20,
    backgroundColor: "#fff",
  },
  title: {
    fontSize: 24,
    fontWeight: "bold",
    marginBottom: 20,
  },
  message: {
    fontSize: 16,
    textAlign: "center",
    color: "#333",
  },
});
